# Obsidian Security — Quick Start Testing Guide

You want to test Obsidian yourself. Here are your options, from easiest to most realistic.

---

## OPTION A: Docker on Your Mac (Easiest — Free — 5 Minutes)

This is the fastest way. The Docker test environment has pre-planted threats (cryptominer, web shell, backdoor, bot traffic) so you can see everything working immediately.

### Prerequisites

1. Install Docker Desktop: https://www.docker.com/products/docker-desktop/
2. Open Terminal

### Steps

```bash
# Go to the project folder
cd "/path/to/Projects with Claude/bastion"

# Build and start the test containers
cd test-environment
docker-compose up -d

# Enter the test container
docker exec -it obsidian-test bash
```

You're now inside a container with Obsidian installed and threats pre-planted.

### Run the Interactive Demo

```bash
./run-demo.sh
```

This walks you through every module step-by-step with explanations. Press Enter to advance through each step.

### Or Run Commands Manually

```bash
# System status
obsidian status

# Full health check (CPU, disk, PHP, MySQL, etc.)
obsidian health check

# Find the hidden cryptominer
obsidian malware scan /home

# Check cron jobs for malicious entries
obsidian malware crons

# Analyze bot traffic in access logs
obsidian bots analyze

# Find vulnerability scanners (Nikto, sqlmap)
obsidian bots scanners

# Check file integrity
obsidian scan full /var/www/html

# Ban a malicious IP
obsidian ban 45.33.32.156 --reason "Rate abuse - 350 req/min" --by george

# View ban list
obsidian ban list

# Whitelist your network
obsidian whitelist add 192.168.1.0/24 --reason "Office LAN"
obsidian whitelist list

# Run the full 7-phase audit
obsidian audit run
```

### Generate a PDF Report

```bash
# Install reportlab (inside the container)
pip3 install reportlab --break-system-packages

# Find the audit ID
ls data/audits/

# Generate PDF
python3 tools/generate-report.py data/audits/AUDIT_ID.json

# The PDF will be at data/reports/
ls data/reports/
```

### Test Multi-Server Sync

The docker-compose includes a second container:

```bash
# In another terminal:
docker exec -it obsidian-agent-test bash

# The agent can receive bans from the primary server
obsidian status
```

### When You're Done

```bash
# Exit the container
exit

# Stop everything
docker-compose down
```

---

## OPTION B: Cheap VPS (Most Realistic — €3-5/month)

A real Linux server is the best way to test. Here are the cheapest options:

### Hetzner Cloud (Recommended for EU — From €3.79/month)

1. Go to https://www.hetzner.com/cloud
2. Sign up for an account
3. Create a server:
   - Location: **Falkenstein** or **Helsinki** (cheapest)
   - Image: **Ubuntu 22.04**
   - Type: **CX22** (2 vCPU, 4GB RAM) — €3.79/month
   - SSH Key: add your public key (or use password)
4. Click **Create & Buy**
5. Note the IP address

### DigitalOcean (Alternative — From $6/month)

1. Go to https://www.digitalocean.com
2. Create a Droplet:
   - Region: **Frankfurt** or **Amsterdam**
   - Image: **Ubuntu 22.04**
   - Size: **Basic $6/month** (1 vCPU, 1GB RAM)
   - Authentication: SSH key

### Oracle Cloud (Free Tier — Permanently Free)

1. Go to https://cloud.oracle.com
2. Sign up (requires credit card but won't charge)
3. Create a Compute instance:
   - Shape: **VM.Standard.A1.Flex** (ARM, 4 OCPU, 24GB RAM — free forever)
   - Image: **Ubuntu 22.04**
   - This is the most powerful free option available anywhere

### Install Obsidian on Your VPS

```bash
# SSH into your server
ssh root@YOUR_SERVER_IP

# Upload the project (from your Mac):
scp -r "/path/to/Projects with Claude/bastion" root@YOUR_SERVER_IP:/opt/obsidian-src

# On the server — install
cd /opt/obsidian-src
sudo bash install.sh
# Choose "standalone" mode when prompted

# IMPORTANT: Verify your IP is whitelisted
obsidian whitelist list
# You should see your server's IPs auto-detected

# Add your home/office IP too
obsidian whitelist add YOUR_HOME_IP "My management access"
```

### Set Up a Realistic Test Environment

```bash
# Install Apache + WordPress for a realistic target
apt update && apt install -y apache2 php php-mysql php-xml
cd /var/www/html
wget https://wordpress.org/latest.tar.gz
tar xzf latest.tar.gz
mv wordpress/* .
rm -rf wordpress latest.tar.gz

# Now run the audit
obsidian audit run

# Generate report
pip3 install reportlab --break-system-packages
obsidian audit report AUDIT_ID
```

### Test Alerts (Telegram)

```bash
# 1. Create a Telegram bot:
#    - Open Telegram, search for @BotFather
#    - Send /newbot
#    - Name it "Obsidian Security Bot" 
#    - Username: obsidian_security_bot (or similar)
#    - Copy the bot token

# 2. Get your chat ID:
#    - Send any message to your bot
#    - Go to: https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
#    - Find "chat":{"id": YOUR_CHAT_ID}

# 3. Configure Obsidian:
nano /opt/obsidian/obsidian.conf
# Add these lines:
#   telegram_bot_token=YOUR_BOT_TOKEN
#   telegram_chat_id=YOUR_CHAT_ID

# 4. Test the alert
obsidian alert test

# You should receive a Telegram message!
```

---

## OPTION C: cPanel/WHM Trial (Most Production-Like)

If you want to test on an actual cPanel server (which is the main target for Obsidian customers):

### cPanel Trial License

1. Get a VPS from Hetzner or DigitalOcean (see Option B)
2. cPanel offers a **15-day free trial**: https://cpanel.net/products/trial/
3. Install cPanel:

```bash
# SSH into your VPS (must be a fresh install, nothing else on it)
cd /home && curl -o latest -L https://secup.cpanel.net/latest && sh latest
```

4. Wait ~30 minutes for installation
5. Access WHM at: `https://YOUR_IP:2087`
6. Create a test account and install WordPress via Softaculous

Then install Obsidian and run the full audit — this is exactly what your clients will experience.

---

## WHAT TO TEST (Checklist)

### Core Functionality

- [ ] `obsidian status` — shows system overview
- [ ] `obsidian health check` — CPU, memory, disk, PHP, MySQL checks
- [ ] `obsidian malware scan /home` — finds suspicious files
- [ ] `obsidian malware crons` — audits cron jobs
- [ ] `obsidian bots analyze` — parses access logs, classifies bot families
- [ ] `obsidian bots scanners` — detects vulnerability scanners
- [ ] `obsidian scan baseline /var/www/html` — creates integrity baseline
- [ ] `obsidian scan full` — checks files against baseline

### Security Features

- [ ] `obsidian ban 1.2.3.4 --reason "test"` — bans an IP
- [ ] `obsidian ban list` — shows active bans
- [ ] `obsidian whitelist list` — shows your server IPs are auto-protected
- [ ] Try banning your own whitelisted IP — **it should refuse**
- [ ] `obsidian whitelist add 10.0.0.0/8 --reason "test CIDR"` — CIDR support

### Audit & Report

- [ ] `obsidian audit run` — runs all 7 phases
- [ ] Check `data/audits/` for the JSON output
- [ ] Generate PDF: `python3 tools/generate-report.py data/audits/AUDIT_FILE.json`
- [ ] Open the PDF — verify bot family breakdown, severity scores, recommendations

### Alerts (if configured)

- [ ] `obsidian alert test` — sends a test alert
- [ ] Ban an IP and verify Telegram notification arrives
- [ ] Check alert deduplication (ban the same IP twice quickly — should only alert once)

---

## RECOMMENDED TESTING ORDER

1. **Start with Docker** (Option A) — get familiar with all commands in a safe sandbox
2. **Then get a VPS** (Option B) — test on a real server with real traffic
3. **Optionally try cPanel** (Option C) — if you want to experience the exact client workflow

The Docker option takes 5 minutes and costs nothing. Start there.
