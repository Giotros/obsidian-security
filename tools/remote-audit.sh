#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Audit — Remote One-Liner
# Run this on a client's server to perform a quick security audit
# without installing anything permanently.
#
# Usage (give this to your client):
#   curl -sL https://yourdomain.com/audit.sh | sudo bash
#
# Or for manual execution:
#   wget -qO- https://yourdomain.com/audit.sh | sudo bash
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

AUDIT_DIR="/tmp/obsidian-audit-$$"
REPORT_FILE="/tmp/obsidian-audit-report-$(date +%Y%m%d_%H%M%S).txt"

cleanup() {
    rm -rf "${AUDIT_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

echo -e "${CYAN}${BOLD}"
echo "════════════════════════════════════════"
echo "  Obsidian Security Audit"
echo "  Quick Server Assessment"
echo "════════════════════════════════════════"
echo -e "${NC}"

# Must be root
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}Please run as root: sudo bash audit.sh${NC}"
    exit 1
fi

mkdir -p "${AUDIT_DIR}"
HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

{
echo "========================================"
echo "  OBSIDIAN SECURITY AUDIT REPORT"
echo "========================================"
echo ""
echo "Server:    ${HOSTNAME}"
echo "Date:      ${TIMESTAMP}"
echo "Scan by:   Obsidian Security Suite"
echo ""
echo "========================================"

# --- SYSTEM INFO ---
echo ""
echo "=== SYSTEM INFORMATION ==="
echo ""
echo "OS:          $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
echo "Kernel:      $(uname -r)"
echo "Uptime:      $(uptime -p 2>/dev/null || uptime)"
echo "CPU Cores:   $(nproc 2>/dev/null || echo '?')"
echo "Memory:      $(free -h 2>/dev/null | grep Mem | awk '{print $3"/"$2}' || echo '?')"

# --- RESOURCE USAGE ---
echo ""
echo "=== RESOURCE USAGE ==="
echo ""
cpu="$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{printf "%.0f", 100 - $8}' || echo '?')"
echo "CPU Usage:   ${cpu}%"

mem_total="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
mem_avail="$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
[[ "${mem_total}" -gt 0 ]] && mem_pct=$(( ((mem_total - mem_avail) * 100) / mem_total )) || mem_pct=0
echo "Memory:      ${mem_pct}%"

echo ""
echo "Disk Usage:"
df -h 2>/dev/null | grep '^/' | while read -r line; do
    echo "  ${line}"
done

# --- PHP ---
echo ""
echo "=== PHP STATUS ==="
echo ""
php_ver="not found"
command -v php &>/dev/null && php_ver="$(php -v 2>/dev/null | head -1)"
echo "PHP:         ${php_ver}"
php_procs="$(pgrep -c 'php-fpm\|php-cgi\|lsphp' 2>/dev/null || echo 0)"
echo "PHP Procs:   ${php_procs}"

# Check for EOL
if echo "${php_ver}" | grep -qE 'PHP 7\.|PHP 5\.'; then
    echo "  [CRITICAL] PHP version is END OF LIFE — upgrade immediately!"
fi

# --- FIREWALL ---
echo ""
echo "=== FIREWALL ==="
echo ""
if command -v csf &>/dev/null; then
    echo "Firewall:    CSF (ConfigServer Firewall)"
    echo "Status:      $(csf -v 2>/dev/null | head -1)"
elif command -v iptables &>/dev/null; then
    rules="$(iptables -L INPUT 2>/dev/null | wc -l || echo 0)"
    echo "Firewall:    iptables (${rules} rules)"
else
    echo "Firewall:    [CRITICAL] NONE DETECTED"
fi

# --- MALWARE SCAN ---
echo ""
echo "=== MALWARE SCAN ==="
echo ""

# Hidden executables
echo "Scanning for hidden executables..."
hidden_bins=0
while IFS= read -r -d '' f; do
    if file "${f}" 2>/dev/null | grep -qiE '(ELF|executable)'; then
        hidden_bins=$(( hidden_bins + 1 ))
        echo "  [CRITICAL] Hidden binary: ${f}"
        echo "    Owner: $(stat -c '%U' "${f}" 2>/dev/null || echo 'unknown')"
    fi
done < <(find /home /tmp /var/tmp /dev/shm -path '*/.*/*' -type f -executable -print0 2>/dev/null)
[[ "${hidden_bins}" -eq 0 ]] && echo "  [OK] No hidden executables found"

# Web shells
echo "Scanning for PHP web shells..."
shells=0
webshell_pat='eval\s*\(\s*base64_decode|eval\s*\(\s*\$_(GET|POST|REQUEST)|system\s*\(\s*\$_|shell_exec\s*\(\s*\$_|c99shell|r57shell|b374k|FilesMan'
while IFS= read -r -d '' f; do
    if grep -lqP "${webshell_pat}" "${f}" 2>/dev/null; then
        shells=$(( shells + 1 ))
        echo "  [CRITICAL] Web shell: ${f}"
    fi
done < <(find /home /var/www -name "*.php" -type f -size -5M -print0 2>/dev/null)
[[ "${shells}" -eq 0 ]] && echo "  [OK] No web shells detected"

# Suspicious crons
echo "Scanning cron jobs..."
cron_bad=0
cron_pat='(curl|wget).*\|.*(sh|bash)|base64.*decode|/\.\w+/|/\.cache/'
for cf in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/cron.d/*; do
    [[ -f "${cf}" ]] || continue
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^# ]] && continue
        if echo "${line}" | grep -qE "${cron_pat}"; then
            cron_bad=$(( cron_bad + 1 ))
            echo "  [CRITICAL] Suspicious cron in $(basename "${cf}"): ${line:0:80}"
        fi
    done < "${cf}"
done
[[ "${cron_bad}" -eq 0 ]] && echo "  [OK] No suspicious cron jobs"

# --- SECURITY CONFIG ---
echo ""
echo "=== SECURITY CONFIGURATION ==="
echo ""

# SSH
if [[ -f /etc/ssh/sshd_config ]]; then
    root_login="$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
    echo "SSH Root Login:    ${root_login:-not set}"
    [[ "${root_login}" == "yes" ]] && echo "  [HIGH] Root SSH login should be disabled"

    pwd_auth="$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
    echo "SSH Password Auth: ${pwd_auth:-not set}"
    [[ "${pwd_auth}" == "yes" ]] && echo "  [MEDIUM] Consider switching to key-based auth"
fi

# World-writable PHP
www_wr="$(find /var/www /home/*/public_html -name "*.php" -perm -o+w 2>/dev/null | wc -l || echo 0)"
echo "World-writable PHP: ${www_wr} files"
[[ "${www_wr}" -gt 0 ]] && echo "  [HIGH] Fix permissions on world-writable PHP files"

# --- BOT TRAFFIC (quick) ---
echo ""
echo "=== TOP IPs BY REQUEST COUNT (recent) ==="
echo ""
for logf in /var/log/apache2/access.log /var/log/httpd/access_log /usr/local/apache/logs/access_log; do
    if [[ -f "${logf}" ]]; then
        tail -5000 "${logf}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
        break
    fi
done

# --- SUMMARY ---
total_issues=$(( hidden_bins + shells + cron_bad ))
[[ "${mem_pct}" -ge 90 ]] && total_issues=$(( total_issues + 1 ))
disk_pct="$(df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' || echo 0)"
[[ "${disk_pct}" -ge 90 ]] && total_issues=$(( total_issues + 1 ))

echo ""
echo "========================================"
echo "  SUMMARY"
echo "========================================"
echo ""
echo "Total issues found: ${total_issues}"
echo ""
if [[ "${total_issues}" -gt 0 ]]; then
    echo "ACTION REQUIRED: This server has security issues"
    echo "that need immediate attention."
else
    echo "No critical issues found. Server appears healthy."
fi
echo ""
echo "========================================"
echo "For a full professional audit with PDF report,"
echo "contact: your@email.com"
echo "========================================"
echo ""
} 2>&1 | tee "${REPORT_FILE}"

echo ""
echo -e "${GREEN}${BOLD}Audit report saved: ${REPORT_FILE}${NC}"
echo -e "Send this file to your security provider for a full analysis."
echo ""
