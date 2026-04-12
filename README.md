# Obsidian — Server Security Suite

A unified, zero-dependency security toolkit for Linux servers. Built in pure Bash for cPanel/WHM hosting environments, but works on any Linux system.

**Born from real incidents:** cryptominer infections, DDoS attacks, aggressive bot traffic, and PHP crashes on production WordPress/WooCommerce servers.

## What It Does

Obsidian combines six security modules into one tool:

| Module | What It Solves |
|--------|---------------|
| **Firewall** | Centralized IP banning across multiple servers (CSF/iptables/WHM) |
| **FileGuard** | File integrity monitoring with SHA256 baselines and real-time inotify |
| **Malware** | Cryptominer detection, web shell scanning, cron job auditing |
| **BotGuard** | Bad bot blocking by User-Agent, rate analysis, scanner detection |
| **Health** | CPU/RAM/disk monitoring, PHP process health, security posture |
| **Sync** | Multi-server ban propagation via pull-based API |

## Quick Start

```bash
# Install (as root)
git clone https://github.com/yourusername/obsidian.git
cd obsidian
sudo bash install.sh

# Check your server
obsidian status
obsidian health check
obsidian malware scan /home
obsidian bots analyze

# Ban an IP (propagates to all servers)
obsidian ban 45.33.32.156 --reason "DDoS source" --by george

# Generate file integrity baseline
obsidian scan baseline /var/www/html --preset wordpress

# Start real-time file monitoring
obsidian scan monitor /var/www/html
```

## Architecture

```
                    ┌─────────────────────┐
                    │   Central Server    │
                    │   (Obsidian API)     │
                    │   CGI on Apache     │
                    └──────┬──────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐
        │ Server 1 │ │ Server 2 │ │ Server N │
        │  Agent   │ │  Agent   │ │  Agent   │
        │          │ │          │ │          │
        │ Modules: │ │ Modules: │ │ Modules: │
        │ Firewall │ │ Firewall │ │ Firewall │
        │ FileGuard│ │ FileGuard│ │ FileGuard│
        │ Malware  │ │ Malware  │ │ Malware  │
        │ BotGuard │ │ BotGuard │ │ BotGuard │
        │ Health   │ │ Health   │ │ Health   │
        └──────────┘ └──────────┘ └──────────┘
              ▲            ▲            ▲
              │  Pull every 60s (configurable)
              └────────────┴────────────┘
```

**Why pull-based?** Agents initiate connections outward, so no inbound ports needed. If the central server goes down, agents keep their existing bans. Works behind NAT without port forwarding.

## Modules

### Firewall — IP Ban Management
```bash
obsidian ban 1.2.3.4 --reason "Brute force" --by admin
obsidian ban unban 1.2.3.4
obsidian ban list
obsidian ban history
obsidian ban emergency 1.2.3.4     # Instant, all layers
obsidian ban import blocklist.txt
obsidian ban export backup.txt
```

Bans apply at two layers: network (CSF/iptables) and application (WHM API). Whitelisted IPs are never banned.

### FileGuard — File Integrity
```bash
obsidian scan baseline /var/www/html --preset wordpress
obsidian scan full
obsidian scan verify /var/www/html/wp-config.php
obsidian scan monitor /var/www/html          # Real-time (inotifywait)
obsidian scan correlate /path/to/file        # Find who changed it
```

Uses SHA256 hashing. Real-time monitoring via inotify kernel events. IP correlation checks Apache, FTP, SSH, and cPanel logs.

### Malware — Threat Detection
```bash
obsidian malware scan /home          # Full scan (all phases)
obsidian malware processes           # Scan running processes
obsidian malware crons               # Audit cron jobs
obsidian malware files /home         # Filesystem scan
obsidian malware quarantine list     # View quarantined files
```

Detects: cryptominers (process patterns + hidden binaries), PHP web shells (30+ signatures), malicious cron jobs, reverse shells, obfuscated payloads.

### BotGuard — Bot Blocking
```bash
obsidian bots analyze                # Full analysis
obsidian bots rates                  # Request rate abuse
obsidian bots scan-ua                # Bad User-Agent scan
obsidian bots scanners               # Vulnerability scanner detection
obsidian bots auto-ban --dry-run     # Preview auto-ban
obsidian bots auto-ban               # Execute auto-ban
obsidian bots htaccess               # Generate .htaccess rules
```

Detects: Bytespider, AhrefsBot, SemrushBot, vulnerability scanners (nikto, sqlmap, wpscan), rate abuse, generic scrapers.

### Health — System Monitoring
```bash
obsidian health check        # Full health check
obsidian health cpu          # CPU & load average
obsidian health memory       # RAM & swap
obsidian health disk         # Disk space & inodes
obsidian health php          # PHP version, processes, config issues
obsidian health connections  # Network connections, SYN flood detection
obsidian health security     # Security posture assessment
```

Detects: PHP EOL versions, aggressive process recycling (extMaxIdleTime), disk space issues, zombie processes, SYN floods, weak SSH config.

### Whitelist — Trusted IPs
```bash
obsidian whitelist add 10.0.0.0/8 --reason "Office network"
obsidian whitelist add 1.2.3.4 --reason "Temp access" --expires 86400
obsidian whitelist remove 1.2.3.4
obsidian whitelist list
obsidian whitelist cleanup   # Remove expired entries
```

Supports CIDR notation with bitwise IP matching. Expiring entries auto-cleanup.

## Alerts

Obsidian sends alerts via Telegram, webhook (JSON with HMAC signature), and email. Configure in `obsidian.conf`:

```ini
telegram_bot_token = 123456:ABC-your-token
telegram_chat_id = -1001234567890
webhook_url = https://hooks.example.com/obsidian
alert_email = admin@example.com
```

Test with: `obsidian alert test`

## Installation Modes

| Mode | Use Case |
|------|----------|
| **Full** | Central server + all modules + API |
| **Agent** | Connects to central + local modules |
| **Standalone** | Local modules only, no sync |

## Requirements

- Linux (Ubuntu, CentOS, AlmaLinux, CloudLinux)
- Bash 4.0+
- Core utilities (grep, awk, sed, curl, sha256sum, openssl)
- Optional: inotify-tools (for real-time file monitoring)
- Optional: Apache with mod_cgid (for central API server)

**Zero external dependencies.** No Python, no Node.js, no databases.

## Project Structure

```
obsidian/
├── obsidian                 # Unified CLI (entry point)
├── obsidian.conf.example    # Configuration template
├── install.sh              # Interactive installer
├── uninstall.sh            # Clean removal
├── lib/
│   ├── common.sh           # Shared utilities (400+ lines)
│   ├── banner.sh           # ASCII art
│   ├── alert.sh            # Multi-channel alert system
│   ├── whitelist.sh        # IP whitelist with CIDR
│   ├── firewall.sh         # IP ban management
│   ├── monitor.sh          # File integrity monitoring
│   ├── correlate.sh        # IP attribution engine
│   ├── malware.sh          # Malware/cryptominer detection
│   ├── botguard.sh         # Bot detection & blocking
│   └── health.sh           # System health monitoring
├── server/
│   └── obsidian-api.sh      # Central API (CGI)
├── agent/
│   └── obsidian-agent.sh    # Sync agent daemon
├── rules/
│   ├── malware-signatures.txt
│   └── bad-bots.txt
└── presets/
    ├── wordpress.conf
    └── woocommerce.conf
```

## Real-World Origin

This tool was built to solve actual problems encountered managing ~10 WordPress/WooCommerce sites on cPanel servers:

1. **Cryptominer infection** — Hidden binary in `.config/.cache/fontconfig/lib-update` with cron respawning every 2 hours, causing PHP crashes
2. **DDoS attack** — 366,000 requests in one day (turned out to be a GuzzleHttp self-DDoS from a plugin loop)
3. **Aggressive bots** — Bytespider, SEO crawlers hammering sites during off-hours
4. **PHP instability** — extMaxIdleTime=10s causing constant process recycling and 503 errors
5. **Multi-server management** — Banning an IP on one server but forgetting the other 9

## License

MIT
