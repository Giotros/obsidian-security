# Obsidian Security Suite — Internal Security Audit

**Date:** April 12, 2026  
**Auditor:** Claude (automated code review)  
**Scope:** All Bash source files, API, installer, agent  
**Verdict:** 4 HIGH, 5 MEDIUM, 2 LOW — no critical RCE found, but several injection paths need hardening

---

## Executive Summary

Obsidian's codebase is solid for a Bash security tool. Input sanitization exists (`sanitize_input()`, `sanitize_path()`, `validate_ip()`), file permissions are mostly correct, and the whitelist-before-ban safety check is properly enforced. However, there are exploitable gaps — particularly around regex injection in grep patterns, weak JSON parsing in the API, and overly permissive directory permissions. None of these are remote code execution vulnerabilities, but several could allow an attacker with API access to corrupt ban lists or bypass rate limiting.

---

## HIGH Severity

### 1. Regex Injection via `grep -v` (firewall.sh, whitelist.sh, obsidian-api.sh)

**What:** When unbanning an IP or removing a whitelist entry, the IP is interpolated directly into a `grep -v` pattern:

```bash
grep -v "^${ip}|" "${BANS_FILE}" > "${BANS_FILE}.tmp"
```

**Risk:** If an attacker can influence the `${ip}` value (e.g., through the API push action), they can inject regex metacharacters. An IP like `1.2.3.*` would match every ban starting with `1.2.3.` — unbanning an entire range instead of one IP.

**Fix:** Use `grep -Fv` (fixed-string match) instead of `grep -v` (regex match):

```bash
grep -Fv "${ip}|" "${BANS_FILE}" > "${BANS_FILE}.tmp"
```

Or better — validate the IP strictly before it ever reaches grep (the CLI does this via `validate_ip()`, but the API uses a weaker regex).

**Affected files:**
- `lib/firewall.sh` — lines 103, 117, 122
- `lib/whitelist.sh` — line 55
- `server/obsidian-api.sh` — lines 192, 227

---

### 2. Unsafe JSON Parsing in API (obsidian-api.sh)

**What:** The API extracts fields from POST bodies using grep regex instead of a JSON parser:

```bash
ip="$(echo "${body}" | grep -oP '"ip"\s*:\s*"\K[^"]+' | head -1)"
```

**Risk:** A crafted JSON payload with escaped quotes, unicode escapes, or strategic newlines could bypass field extraction or inject unexpected values. Example: `{"ip": "1.2.3.4\", \"reason\": \"injected"}` could confuse the parser.

**Fix:** Since Obsidian is zero-dependency, you can't use `jq`. But you should add strict post-extraction validation — call `validate_ip()` (the proper one from common.sh, not the weak regex) on every extracted IP before using it:

```bash
ip="$(echo "${body}" | grep -oP '"ip"\s*:\s*"\K[^"]+' | head -1)"
if ! validate_ip "${ip}"; then
    send_error "400" "Invalid IP"
fi
```

Also sanitize `reason` and `agent_name` with `sanitize_input()` after extraction.

---

### 3. Data Directory Permissions Too Open (install.sh)

**What:** The installer sets:

```bash
chmod -R 770 "${DATA_DIR}" "${LOG_DIR}"
```

**Risk:** 770 means any user in the obsidian group can read and write ban lists, audit data, API tokens, and logs. If Apache/nginx or any compromised service shares the group, an attacker can modify ban records or read the API token.

**Fix:** Use 750 for directories (group can read but not write) and 640 for files:

```bash
chmod -R 750 "${DATA_DIR}" "${LOG_DIR}"
```

Or even 700 if only root runs obsidian commands. The API token file is already 600 (correct), but the parent directory's 770 partially undermines that.

---

### 4. Weak IP Validation in API vs CLI

**What:** The CLI uses `validate_ip()` from common.sh which properly checks each octet is 0-255. The API uses a simpler regex:

```bash
if [[ ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
```

**Risk:** This accepts `999.999.999.999` as a valid IP. While not directly exploitable, invalid IPs in ban lists could cause firewall errors or confusion.

**Fix:** Replace the inline regex with a call to `validate_ip()` from common.sh (which is already sourced by the API script).

---

## MEDIUM Severity

### 5. Rate Limit Race Condition (obsidian-api.sh)

**What:** The rate limiter reads the count, checks the limit, then appends the new timestamp — three separate operations with no locking:

```bash
# Read + count
while IFS= read -r timestamp; do ...
# Check
if [[ "${count}" -ge "${MAX_REQUESTS_PER_MINUTE}" ]]; then
# Write
echo "${now}" >> "${rate_file}"
```

**Risk:** Under concurrent requests, multiple requests can pass the rate check simultaneously before any of them write their timestamp. This allows burst bypassing of the 100 req/min limit.

**Fix:** Wrap the entire check-and-write in a file lock using `flock`:

```bash
(
    flock -x 200
    # ... rate limit logic here ...
) 200>"${rate_file}.lock"
```

---

### 6. Webhook Secret in Shell Command (alert.sh)

**What:** The webhook HMAC secret is passed directly to openssl:

```bash
signature="$(echo -n "${payload}" | openssl dgst -sha256 -hmac "${webhook_secret}" ...)"
```

**Risk:** If the secret contains shell metacharacters (backticks, `$()`), they could be interpreted. Unlikely in practice since secrets are typically hex strings, but defensively unsafe.

**Fix:** Pipe the secret via stdin or use a temp file:

```bash
signature="$(echo -n "${payload}" | openssl dgst -sha256 -hmac "$(printf '%s' "${webhook_secret}")" ...)"
```

Or validate that the secret contains only safe characters when loading from config.

---

### 7. Agent Name Header Not Sanitized (obsidian-api.sh)

**What:** The `X-Agent-Name` HTTP header is used directly without sanitization:

```bash
local agent_name="${HTTP_X_AGENT_NAME:-unknown}"
echo "${agent_name}|${timestamp}|${client_ip}" >> "${temp}"
```

**Risk:** A malicious agent name containing pipes (`|`) or newlines could corrupt the heartbeat file format, causing parsing errors or log injection.

**Fix:** Run it through `sanitize_input()`:

```bash
local agent_name
agent_name="$(sanitize_input "${HTTP_X_AGENT_NAME:-unknown}")"
```

---

### 8. Alert Text Not Escaped for Telegram Markdown (alert.sh)

**What:** Alert fields like `${module}`, `${title}`, `${message}` are interpolated into Telegram MarkdownV2 without escaping special characters (`*`, `_`, `` ` ``, `[`, `]`).

**Risk:** If a malware file path contains markdown characters (which is common — e.g., `/tmp/.hidden_*`), the Telegram message will render incorrectly or fail to send.

**Fix:** Add a `telegram_escape()` function that escapes MarkdownV2 special characters, or switch to HTML parse mode which is easier to escape.

---

### 9. No CSRF Protection on API

**What:** The CGI API authenticates via Bearer token only. There's no CSRF token, Origin header check, or SameSite restriction.

**Risk:** If an admin has the API token stored in their browser (e.g., via a monitoring dashboard), a malicious page could make cross-origin requests to ban/unban IPs.

**Practical risk is low** because: (a) the API is typically not browser-facing, (b) the token must be in the Authorization header which cross-origin requests can't easily set without CORS.

**Fix (optional):** Add an `Origin` or `Referer` check, or require a custom header (e.g., `X-Obsidian-Request: 1`) that browsers won't send cross-origin without CORS preflight.

---

## LOW Severity

### 10. Information Disclosure in Error Messages (obsidian-api.sh)

**What:** Error responses reveal system state:

```bash
send_error "500" "Server token not configured"
send_error "400" "Unknown action: ${action}"
```

**Fix:** Use generic messages: `"Authentication error"`, `"Bad request"`. Log details server-side only.

---

### 11. Token Comparison Timing (obsidian-api.sh)

**What:** Token comparison uses `[[ "${token}" != "${stored_token}" ]]`. In Bash, string comparison is effectively constant-time for same-length strings (no short-circuit at the character level), so this is not practically exploitable. But it's worth noting for defense-in-depth.

**Fix (optional):** Compare hashes instead:

```bash
token_hash="$(echo -n "${token}" | sha256sum | cut -d' ' -f1)"
stored_hash="$(echo -n "${stored_token}" | sha256sum | cut -d' ' -f1)"
[[ "${token_hash}" == "${stored_hash}" ]]
```

---

## Already Done Right

These are things the codebase handles well:

- **Whitelist enforcement before banning** — `ban_ip()` checks `is_whitelisted()` before applying any ban. Emergency bans also check whitelist.
- **Private IP protection** — Can't ban RFC1918 addresses (10.x, 172.16-31.x, 192.168.x)
- **API token generation** — Uses `openssl rand -hex 32` (256-bit entropy). Stored at 600 permissions.
- **POST body size limit** — API reads max 1MB (`head -c "${length}"`), preventing memory exhaustion.
- **Systemd hardening** — Service file uses `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`.
- **Input sanitization exists** — `sanitize_input()` strips `;|&\`$(){}><` and truncates to 512 chars.
- **Path sanitization** — `sanitize_path()` removes `../` traversal and null bytes.
- **Alert deduplication** — Same alert won't fire twice within cooldown period (300s default).
- **Alert rate limiting** — Max 30 alerts/minute prevents alert flooding.
- **File locking** — Uses atomic `mkdir` for locks with stale lock detection (120s timeout).
- **CIDR support** — `ip_in_cidr()` does proper bitwise math for subnet matching.

---

## Recommended Fix Priority

| Priority | Issue | Effort | Impact |
|----------|-------|--------|--------|
| **Fix now** | #1 grep -Fv | 5 min | Prevents regex injection in ban/whitelist ops |
| **Fix now** | #4 API IP validation | 5 min | One-line change, use validate_ip() |
| **Fix now** | #7 Agent name sanitization | 2 min | One-line change |
| **Fix soon** | #2 Post-extraction validation | 15 min | Add sanitize_input() calls after JSON extraction |
| **Fix soon** | #3 Directory permissions | 5 min | Change 770 to 750 |
| **Fix soon** | #5 Rate limit locking | 10 min | Add flock wrapper |
| **Nice to have** | #8 Telegram escaping | 15 min | Cosmetic — alerts might render wrong |
| **Nice to have** | #10 Error messages | 5 min | Minor info disclosure |
| **Optional** | #6 Webhook secret | 5 min | Low practical risk |
| **Optional** | #9 CSRF | 10 min | Low practical risk for CGI API |
| **Optional** | #11 Token timing | 5 min | Not practically exploitable in Bash |

---

## Summary

The codebase is in good shape for a Bash tool. The most important fixes are switching `grep -v` to `grep -Fv` everywhere (prevents regex injection), calling `validate_ip()` in the API (instead of the weak inline regex), and tightening directory permissions from 770 to 750. These three changes take about 15 minutes total and close the most meaningful attack surface.

Nothing here is a show-stopper or a reason to delay launching. These are hardening improvements, not critical vulnerabilities.
