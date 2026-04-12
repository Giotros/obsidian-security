# Obsidian — Interview Preparation Guide

## The 30-Second Elevator Pitch

"I built Obsidian — a unified server security suite in pure Bash — because I was managing 10 WordPress sites on cPanel and we got hit by a DDoS attack. There was no single tool that could ban an IP across all servers, detect cryptominers, block aggressive bots, AND monitor file integrity. So I built one. Zero dependencies, installs in 30 seconds, runs on any Linux server. Six modules: firewall management, file integrity monitoring, malware detection, bot blocking, health monitoring, and multi-server sync."

## The Full Story (for "Tell me about a project")

"I manage about 10 WordPress and WooCommerce sites on cPanel servers. One night we got DDoS'd — I was banning IPs one server at a time with CSF, which took forever. Then a client's server had a hidden cryptominer in `/home/user/.config/.cache/fontconfig/lib-update` that was eating all the CPU, crashing PHP, and respawning via cron every 2 hours. On top of that, bots like Bytespider were hammering our sites at 3am when nobody was watching, and the PHP extMaxIdleTime was set to 10 seconds — so processes were being killed and restarted constantly, causing 503 errors.

I realized I needed one tool that does everything: ban IPs across all servers at once, detect cryptominers and web shells, block bad bots automatically, check PHP config issues, and alert me on Telegram. So I built Obsidian — a modular security suite in pure Bash, because on cPanel servers you can't install Python or Go — but Bash and core utilities are always there."

## Architecture (draw this on whiteboard)

```
┌──────────────────────────────────────────────────────────┐
│                    OBSIDIAN CLI                           │
│  obsidian <module> <command> [options]                     │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│ Firewall │ FileGuard│ Malware  │ BotGuard │ Health       │
│          │          │          │          │              │
│ CSF/     │ SHA256   │ Process  │ UA scan  │ CPU/RAM/Disk │
│ iptables │ baseline │ scanner  │ Rate     │ PHP config   │
│ WHM API  │ inotify  │ Cron     │ analysis │ Connection   │
│          │ IP corr. │ audit    │ Scanner  │ monitoring   │
│          │          │ FS scan  │ detect   │ Security     │
│          │          │ Quarant. │ Auto-ban │ posture      │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│                 SHARED LIBRARY (lib/)                     │
│  common.sh · alert.sh · whitelist.sh · banner.sh         │
│  Logging · Config · IP validation · CIDR · Locking       │
├──────────────────────────────────────────────────────────┤
│              MULTI-SERVER SYNC                           │
│  Central API (CGI) ←── Pull every 60s ──→ Agent daemons │
└──────────────────────────────────────────────────────────┘
```

## Module-by-Module Technical Deep Dive

### 1. Firewall Module (firewall.sh)
**What it does:** Manages IP bans across multiple layers — network (CSF/iptables) and application (WHM API).

**Key design decisions:**
- Two-layer banning because attackers can bypass one layer (e.g., through CDN)
- Firewall auto-detection: tries CSF first → falls back to iptables → falls back to nftables
- File locking with `mkdir` (atomic operation) to prevent race conditions
- Emergency ban path that bypasses sync delay for active attacks

**Code patterns to reference:**
- `ban_ip()` — validates, checks whitelist, applies both layers, records history
- `apply_firewall_ban()` — uses `detect_firewall()` then case statement for each type
- Pipe-delimited flat files instead of database (zero dependencies)

### 2. FileGuard Module (monitor.sh + correlate.sh)
**What it does:** SHA256 integrity monitoring with IP attribution.

**Key design decisions:**
- Two-tier monitoring: real-time (inotifywait) + periodic full scan (every 6 hours)
- inotify for immediate detection; full scan catches queue overflows
- IP correlation engine checks 4 log sources: Apache, FTP, SSH, cPanel
- Confidence scoring — closer timestamp = higher score

**Code patterns:**
- `generate_baseline()` — `find | sha256sum` with permissions and ownership metadata
- `full_integrity_scan()` — loads baseline into associative arrays, compares current state
- `correlate_ip()` — time-window cross-reference across 4 log sources
- Severity classification by file path (wp-config.php = CRITICAL)

### 3. Malware Module (malware.sh)
**What it does:** Detects cryptominers, web shells, malicious crons, suspicious processes.

**Born from real incident:** Client had `/home/mybagonline/.config/.cache/fontconfig/lib-update` — a cryptominer binary hidden in a dot directory, consuming CPU, crashing PHP, with a cron job restarting it every 2 hours.

**Three scanning phases:**
1. **Process scanner** — checks `ps aux` for: known miner names, binaries in hidden dirs, deleted binary indicators, high CPU by non-root users, reverse shell patterns
2. **Cron job auditor** — reads all user crontabs + system crons, flags: curl|wget piped to shell, base64/eval patterns, binaries in dot dirs, suspiciously frequent execution
3. **Filesystem scanner** — finds: hidden ELF executables, PHP web shells (30+ signatures), world-writable web files, ownership anomalies

**Code patterns:**
- `scan_processes()` — 7 detection patterns including `/proc/PID/exe` deleted binary check
- `is_suspicious_cron_entry()` — 7 pattern matchers for common attack patterns
- Quarantine system — moves files with metadata preservation for safe analysis

### 4. BotGuard Module (botguard.sh)
**What it does:** Detects and blocks malicious bots by User-Agent, request rate, and scanning patterns.

**Born from real issue:** Bytespider, AhrefsBot, and vulnerability scanners hammering sites at 3am.

**Three detection methods:**
1. **Rate analysis** — counts requests per IP in time window, flags above threshold
2. **User-Agent matching** — regex patterns against known bad bots (50+ signatures)
3. **Vulnerability scanner detection** — detects .env probing, path traversal, SQLi, XSS attempts

**Code patterns:**
- `analyze_request_rates()` — parses Apache logs, builds IP count associative array
- `auto_ban_bots()` — dry-run mode for safety, integrates with firewall module
- `generate_htaccess_rules()` — outputs ready-to-use Apache rewrite rules

### 5. Health Module (health.sh)
**What it does:** Monitors CPU, memory, disk, PHP processes, network connections, security posture.

**Born from real issues:** PHP extMaxIdleTime=10s causing 503s, disk 90% full, PHP 7.4 EOL.

**Checks:**
- CPU/load vs core count
- Memory with swap analysis
- Disk space + inode usage
- PHP version EOL detection (flags 7.x as critical)
- PHP-FPM config issues (pm.max_requests too low, extMaxIdleTime too aggressive)
- Network connection analysis (SYN flood detection, per-IP connection counting)
- Security posture (firewall, SSH config, fail2ban, world-writable dirs)

### 6. Multi-Server Sync (agent + server API)
**What it does:** Pull-based synchronization — agents poll central API every 60 seconds.

**Why pull-based and not push:**
- No inbound ports needed on agents (works behind NAT)
- Central server failure is graceful (agents keep existing bans)
- Simpler security model (agents authenticate outbound only)

**Code patterns:**
- CGI API on existing Apache — no new dependencies or daemons
- Bearer token auth with 256-bit tokens (`openssl rand -hex 32`)
- Rate limiting per IP (100 requests/minute)
- Heartbeat mechanism for agent monitoring

## Hard Interview Questions & Answers

### Q: "Why Bash and not Go or Python?"
A: "Three reasons. First, target audience — hosting admins on cPanel run Bash daily; Go requires compilation, Python isn't guaranteed at consistent versions. Second, zero dependencies — the only external package is inotify-tools for real-time monitoring, everything else uses core utilities. Third, native integration — the tools it manages (CSF, iptables, WHM API) are all shell-callable. In Python I'd be wrapping subprocess calls anyway."

### Q: "How do you handle concurrent writes to bans.txt?"
A: "File locking using `mkdir` as a mutex. `mkdir` is atomic on Linux — two processes can't both succeed on the same path. If a process crashes holding the lock, there's a stale lock detector that checks the lock directory's modification time — if older than 120 seconds, it breaks the lock."

### Q: "What if inotifywait misses events due to queue overflow?"
A: "Two-tier design. Real-time inotify catches immediate changes. Every 6 hours, a full scan SHA256-hashes every monitored file against the baseline. The full scan catches anything the real-time monitor missed. The tradeoff is detection delay — up to 6 hours for missed events — but it guarantees nothing is permanently missed."

### Q: "Your malware scanner uses pattern matching. Can't attackers evade it?"
A: "Absolutely. Pattern-based detection is a first line, not a complete solution. An obfuscated web shell or a renamed binary will bypass string matching. That's why the malware module has multiple layers: process behavior analysis (high CPU, hidden directories, deleted binaries), cron job auditing (execution patterns, not just content), and file integrity monitoring (any change triggers investigation). It's defense in depth. For a complete solution I'd add ClamAV integration, but that breaks the zero-dependency constraint."

### Q: "The 60-second sync interval means there's a window where an attacker is banned on one server but active on another."
A: "Correct — 60 seconds worst case. But compare to manual process: SSH into each of 10 servers, run csf -d, that's 5-10 minutes. I reduced the window from minutes to seconds. For active attacks, there's `obsidian ban emergency` which does an API push immediately, bypassing the sync cycle. If I needed sub-second propagation, I'd move to WebSocket push or Redis pub/sub — but that adds dependencies."

### Q: "How does CIDR matching work in Bash without libraries?"
A: "`ip_to_num()` converts an IP to a 32-bit integer using bit shifting: `(octet1 << 24) | (octet2 << 16) | (octet3 << 8) | octet4`. For a CIDR like 10.0.0.0/8, I build a bitmask by shifting 0xFFFFFFFF left by (32 - prefix). Then: `(target_ip AND mask) == (network_ip AND mask)`. If true, the IP is in the range."

### Q: "What would you change for 1000 servers instead of 10?"
A: "Four things: push-based notifications (webhook or message queue) instead of polling, a proper database (PostgreSQL) instead of flat files, horizontal API scaling behind a load balancer, and regional relay servers to reduce cross-datacenter latency. The modular architecture means each module can be replaced independently."

### Q: "How do you test this?"
A: "Docker environment that simulates a compromised server — plants a fake cryptominer, malicious cron job, web shell, generates access logs with bot traffic. The run-demo.sh script walks through all modules interactively. For production testing, each module can run in dry-run mode."

## Project Stats

| Metric | Value |
|--------|-------|
| Total Bash lines | ~4,000+ |
| Modules | 6 (firewall, fileguard, malware, botguard, health, sync) |
| Library files | 10 |
| CLI commands | 40+ |
| Detection patterns | 80+ (malware + bots combined) |
| Alert channels | 3 (Telegram, webhook, email) |
| Dependencies | 0 (inotify-tools optional) |
| Install time | ~30 seconds |
| Language | 100% Bash |

## Key Technical Vocabulary

- **Defense in depth** — multiple detection layers so bypassing one doesn't defeat the system
- **Pull-based architecture** — agents initiate connections, simpler than push (NAT-friendly)
- **CGI (Common Gateway Interface)** — running scripts as HTTP endpoints through Apache
- **Flat file database** — text files as data storage, no database server needed
- **inotify** — Linux kernel subsystem for filesystem event notification
- **Mutex / file locking** — preventing concurrent access using `mkdir` atomic operation
- **CIDR bitwise matching** — IP range checking using AND mask operations
- **HMAC signature** — webhook payload authentication using shared secret
- **Signal handling** — `trap` for graceful shutdown and config reload (SIGTERM, SIGHUP)
- **Alert deduplication** — preventing alert storms by tracking send timestamps
- **Rate limiting** — per-IP request counting with sliding time window
- **Quarantine** — safely isolating suspicious files with metadata preservation
