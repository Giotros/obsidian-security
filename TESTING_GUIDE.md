# Obsidian Security — Testing Guide

## Quick Start (Docker — Recommended)

The safest way to test everything end-to-end without touching production.

```bash
cd test-environment
docker-compose up -d
docker exec -it obsidian-primary bash
./run-demo.sh
```

This gives you two containers with pre-planted threats (cryptominer, web shell, malicious cron, bot traffic logs) and walks through all 9 modules interactively.

---

## Testing on a Real Server

### Prerequisites

- Root or sudo access
- cPanel/WHM (optional — works standalone too)
- Bash 4.0+

### Step 1: Install

```bash
sudo bash install.sh
```

Choose "standalone" mode for testing. The installer will:
- Auto-detect your server IPs and whitelist them
- Whitelist localhost (127.0.0.1, ::1)
- Optionally configure Telegram alerts

### Step 2: Verify Your IP Is Protected

**Before doing anything else**, confirm the whitelist:

```bash
obsidian whitelist list
```

You should see your server IPs, localhost, and any IPs you added. To add your management IP:

```bash
obsidian whitelist add YOUR_OFFICE_IP "Management access"
```

To add an entire range:

```bash
obsidian whitelist add 10.0.0.0/8 "Internal network"
```

**The whitelist is checked before every ban.** A whitelisted IP cannot be banned — the `ban_ip()` function returns immediately with a warning.

### Step 3: Run an Audit

```bash
obsidian audit run
```

This runs all 7 scan phases and produces a JSON file in `data/audits/`.

### Step 4: Generate PDF Report

```bash
# Install reportlab (one time)
pip3 install reportlab

# Generate from the latest audit
obsidian audit report <audit_id>
```

### Step 5: Test Individual Modules

```bash
# Health check
obsidian health

# Malware scan (specific path)
obsidian malware scan /home

# Bot analysis
obsidian bots analyze

# Bot analysis with auto-ban (DRY RUN first!)
obsidian bots auto-ban --dry-run

# File integrity baseline
obsidian scan baseline /home/user/public_html

# Check integrity against baseline
obsidian scan check
```

### Step 6: Test Alerts

```bash
# Configure Telegram (if not done during install)
# Edit /opt/obsidian/obsidian.conf:
#   telegram_bot_token=YOUR_BOT_TOKEN
#   telegram_chat_id=YOUR_CHAT_ID

# Test alert manually
obsidian alert test

# Alerts are also triggered automatically by:
# - Any IP ban (HIGH severity)
# - Malware detection (CRITICAL)
# - File integrity changes (MEDIUM-HIGH)
# - DDoS pattern detection (CRITICAL)
```

---

## What Gets Banned and What Doesn't

### Will NOT be banned (protected):
- Any IP in the whitelist file
- Server's own IPs (auto-detected on install)
- Localhost (127.0.0.1, ::1)
- Private/RFC1918 IPs by default (10.x, 172.16-31.x, 192.168.x)
- Any CIDR range you've whitelisted

### Can be banned (if detected as malicious):
- External IPs exceeding rate thresholds
- IPs with known bad User-Agent strings
- IPs performing vulnerability scanning
- IPs identified by correlation engine as attack sources

### Multi-server ban distribution:
- Bans are synced to other servers via the agent/API system
- Each receiving server applies its OWN whitelist before accepting a synced ban
- So even if Server A bans an IP, Server B will reject it if that IP is whitelisted on B

---

## Safe Testing Checklist

1. Whitelist your own IP first: `obsidian whitelist add YOUR_IP "Testing"`
2. Use `--dry-run` on auto-ban commands
3. Check `obsidian whitelist list` to verify protection
4. Test in Docker first if unsure
5. Review `logs/obsidian.log` for all actions
6. Use `obsidian status` to see current state (bans, whitelist, alerts)
