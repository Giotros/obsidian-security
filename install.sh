#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Installer
# Interactive installation for cPanel/WHM and standard Linux servers
# Zero dependencies (except inotify-tools for file monitoring)
# =============================================================================

set -euo pipefail

readonly INSTALL_DIR="/opt/obsidian"
readonly DATA_DIR="${INSTALL_DIR}/data"
readonly LOG_DIR="${INSTALL_DIR}/logs"
readonly RUN_DIR="/var/run/obsidian"
readonly SYSTEM_USER="obsidian"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
   ____  __         _     ___
  / __ \/ /_  _____(_)___/ (_)___ _____
 / / / / __ \/ ___/ / __  / / __ `/ __ \
/ /_/ / /_/ (__  ) / /_/ / / /_/ / / / /
\____/_.___/____/_/\__,_/_/\__,_/_/ /_/
BANNER
echo -e "${NC}"
echo -e "  ${CYAN}Server Security Suite — Installer${NC}\n"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

echo -e "${BOLD}[1/7] Pre-flight checks${NC}"

# Must be root
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "  ${RED}✗ Must run as root (use sudo)${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓ Running as root${NC}"

# Check OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo -e "  ${GREEN}✓ OS: ${PRETTY_NAME:-Linux}${NC}"
else
    echo -e "  ${YELLOW}⚠ Could not detect OS${NC}"
fi

# Check for cPanel
CPANEL=false
if [[ -f "/usr/local/cpanel/version" ]]; then
    CPANEL=true
    CPANEL_VERSION="$(cat /usr/local/cpanel/version 2>/dev/null || echo 'unknown')"
    echo -e "  ${GREEN}✓ cPanel detected: ${CPANEL_VERSION}${NC}"
else
    echo -e "  ${BLUE}ℹ cPanel not detected (standalone mode)${NC}"
fi

# Detect firewall
FIREWALL="none"
if command -v csf &>/dev/null; then
    FIREWALL="csf"
    echo -e "  ${GREEN}✓ Firewall: CSF (ConfigServer Firewall)${NC}"
elif command -v iptables &>/dev/null; then
    FIREWALL="iptables"
    echo -e "  ${GREEN}✓ Firewall: iptables${NC}"
elif command -v nft &>/dev/null; then
    FIREWALL="nftables"
    echo -e "  ${GREEN}✓ Firewall: nftables${NC}"
else
    echo -e "  ${YELLOW}⚠ No firewall detected — bans will be recorded but not enforced${NC}"
fi

# Check for inotify-tools (optional but recommended)
INOTIFY=false
if command -v inotifywait &>/dev/null; then
    INOTIFY=true
    echo -e "  ${GREEN}✓ inotify-tools installed (real-time monitoring available)${NC}"
else
    echo -e "  ${YELLOW}⚠ inotify-tools not installed (real-time monitoring unavailable)${NC}"
    echo -e "    Install with: ${BOLD}apt install inotify-tools${NC} or ${BOLD}yum install inotify-tools${NC}"
fi

# =============================================================================
# INSTALLATION MODE
# =============================================================================

echo -e "\n${BOLD}[2/7] Installation mode${NC}"
echo ""
echo "  Select installation mode:"
echo "    1) Full install (all modules + sync agent + server API)"
echo "    2) Agent only (sync agent + local modules, no API server)"
echo "    3) Standalone (local modules only, no multi-server sync)"
echo ""

read -rp "  Choice [1/2/3]: " install_mode
install_mode="${install_mode:-1}"

case "${install_mode}" in
    1) echo -e "  ${GREEN}✓ Full install selected${NC}" ;;
    2) echo -e "  ${GREEN}✓ Agent-only install selected${NC}" ;;
    3) echo -e "  ${GREEN}✓ Standalone install selected${NC}" ;;
    *) echo -e "  ${RED}Invalid choice${NC}"; exit 1 ;;
esac

# =============================================================================
# CREATE SYSTEM USER
# =============================================================================

echo -e "\n${BOLD}[3/7] System setup${NC}"

if ! id "${SYSTEM_USER}" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d "${INSTALL_DIR}" -M "${SYSTEM_USER}" 2>/dev/null || true
    echo -e "  ${GREEN}✓ Created system user: ${SYSTEM_USER}${NC}"
else
    echo -e "  ${GREEN}✓ System user exists: ${SYSTEM_USER}${NC}"
fi

# =============================================================================
# INSTALL FILES
# =============================================================================

echo -e "\n${BOLD}[4/7] Installing files${NC}"

# Create directories
mkdir -p "${INSTALL_DIR}"/{lib,agent,server,rules,presets,data,logs}
mkdir -p "${RUN_DIR}"

# Copy files from current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Core libraries
cp "${SCRIPT_DIR}"/lib/*.sh "${INSTALL_DIR}/lib/"
echo -e "  ${GREEN}✓ Libraries installed${NC}"

# CLI tool
cp "${SCRIPT_DIR}/obsidian" "${INSTALL_DIR}/obsidian"
chmod +x "${INSTALL_DIR}/obsidian"
echo -e "  ${GREEN}✓ CLI tool installed${NC}"

# Rules
if [[ -d "${SCRIPT_DIR}/rules" ]]; then
    cp "${SCRIPT_DIR}"/rules/* "${INSTALL_DIR}/rules/" 2>/dev/null || true
    echo -e "  ${GREEN}✓ Detection rules installed${NC}"
fi

# Presets
if [[ -d "${SCRIPT_DIR}/presets" ]]; then
    cp "${SCRIPT_DIR}"/presets/* "${INSTALL_DIR}/presets/" 2>/dev/null || true
    echo -e "  ${GREEN}✓ Monitoring presets installed${NC}"
fi

# Agent (modes 1 and 2)
if [[ "${install_mode}" != "3" ]]; then
    cp "${SCRIPT_DIR}"/agent/*.sh "${INSTALL_DIR}/agent/"
    chmod +x "${INSTALL_DIR}/agent/"*.sh
    echo -e "  ${GREEN}✓ Sync agent installed${NC}"
fi

# Server API (mode 1 only)
if [[ "${install_mode}" == "1" ]]; then
    cp "${SCRIPT_DIR}"/server/*.sh "${INSTALL_DIR}/server/"
    chmod +x "${INSTALL_DIR}/server/"*.sh
    echo -e "  ${GREEN}✓ API server installed${NC}"
fi

# Symlink to /usr/local/bin
ln -sf "${INSTALL_DIR}/obsidian" /usr/local/bin/obsidian
echo -e "  ${GREEN}✓ CLI available as 'obsidian' command${NC}"

# =============================================================================
# CONFIGURATION
# =============================================================================

echo -e "\n${BOLD}[5/7] Configuration${NC}"

CONF_FILE="${INSTALL_DIR}/obsidian.conf"

if [[ ! -f "${CONF_FILE}" ]]; then
    # Generate API token
    API_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | xxd -p | tr -d '\n' | head -c 64)"

    cat > "${CONF_FILE}" << CONF
# =============================================================================
# Obsidian Security Suite — Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# =============================================================================

# --- General ---
hostname = $(hostname -f 2>/dev/null || hostname)
log_level = INFO

# --- Firewall ---
firewall = ${FIREWALL}
allow_ban_private = false
auto_ban_critical = false

# --- File Monitoring ---
monitor_path = /var/www
scan_interval = 21600
monitor_preset = wordpress

# --- Alerts ---
alert_min_severity = MEDIUM

# Telegram (get token from @BotFather, chat_id from @userinfobot)
telegram_bot_token =
telegram_chat_id =

# Webhook (receives JSON POST)
webhook_url =
webhook_secret =

# Email
alert_email =

# --- BotGuard ---
rate_window = 60
rate_max_requests = 120
rate_ban_threshold = 300

# --- Health Thresholds ---
cpu_warn_threshold = 80
cpu_crit_threshold = 95
mem_warn_threshold = 80
mem_crit_threshold = 95
disk_warn_threshold = 80
disk_crit_threshold = 90
php_min_idle_time = 30

# --- API Server (mode 1 only) ---
api_token = ${API_TOKEN}
api_port = 443

# --- Sync Agent (modes 1 & 2) ---
# central_url = https://your-central-server.com/cgi-bin/obsidian-api.sh
# central_token = ${API_TOKEN}
# sync_interval = 60
# agent_name = $(hostname -s)
CONF

    echo -e "  ${GREEN}✓ Configuration created: ${CONF_FILE}${NC}"
    echo -e "  ${CYAN}  API Token: ${API_TOKEN:0:16}...${NC}"
else
    echo -e "  ${YELLOW}⚠ Config exists, keeping current: ${CONF_FILE}${NC}"
fi

# Agent config
if [[ "${install_mode}" != "3" ]]; then
    AGENT_CONF="${INSTALL_DIR}/agent.conf"
    if [[ ! -f "${AGENT_CONF}" ]]; then
        cat > "${AGENT_CONF}" << ACONF
# Obsidian Sync Agent Configuration
# central_url = https://your-central-server.com/cgi-bin/obsidian-api.sh
# central_token = YOUR_API_TOKEN_HERE
sync_interval = 60
agent_name = $(hostname -s)
ACONF
        echo -e "  ${GREEN}✓ Agent config created: ${AGENT_CONF}${NC}"
    fi
fi

# =============================================================================
# ALERT SETUP (optional)
# =============================================================================

echo -e "\n${BOLD}[6/7] Alert configuration (optional)${NC}"
echo ""
read -rp "  Configure Telegram alerts now? [y/N]: " setup_telegram

if [[ "${setup_telegram}" =~ ^[yY] ]]; then
    read -rp "  Telegram Bot Token: " tg_token
    read -rp "  Telegram Chat ID: " tg_chat

    if [[ -n "${tg_token}" ]] && [[ -n "${tg_chat}" ]]; then
        sed -i "s/^telegram_bot_token =.*/telegram_bot_token = ${tg_token}/" "${CONF_FILE}"
        sed -i "s/^telegram_chat_id =.*/telegram_chat_id = ${tg_chat}/" "${CONF_FILE}"
        echo -e "  ${GREEN}✓ Telegram configured${NC}"
    fi
fi

# =============================================================================
# APACHE CGI SETUP (mode 1 — API server)
# =============================================================================

if [[ "${install_mode}" == "1" ]]; then
    echo -e "\n  ${BOLD}Setting up Apache CGI for API...${NC}"

    CGI_DIR="/usr/lib/cgi-bin"
    if [[ "${CPANEL}" == true ]]; then
        CGI_DIR="/usr/local/cpanel/cgi-sys"
    fi
    [[ ! -d "${CGI_DIR}" ]] && CGI_DIR="/var/www/cgi-bin"

    mkdir -p "${CGI_DIR}"
    cp "${INSTALL_DIR}/server/obsidian-api.sh" "${CGI_DIR}/obsidian-api.sh"
    chmod 755 "${CGI_DIR}/obsidian-api.sh"

    # Enable required Apache modules
    if command -v a2enmod &>/dev/null; then
        a2enmod cgid headers 2>/dev/null || true
    fi

    echo -e "  ${GREEN}✓ API endpoint: ${CGI_DIR}/obsidian-api.sh${NC}"
fi

# =============================================================================
# SYSTEMD SERVICE
# =============================================================================

echo -e "\n${BOLD}[7/7] Service setup${NC}"

# Main Obsidian systemd service (for agent mode)
if [[ "${install_mode}" != "3" ]]; then
    cat > /etc/systemd/system/obsidian-agent.service << SERVICE
[Unit]
Description=Obsidian Security Suite — Sync Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/agent/obsidian-agent.sh start
ExecStop=${INSTALL_DIR}/agent/obsidian-agent.sh stop
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/data ${INSTALL_DIR}/logs ${RUN_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload 2>/dev/null || true
    echo -e "  ${GREEN}✓ Systemd service created: obsidian-agent${NC}"
    echo -e "    Start with: ${BOLD}systemctl start obsidian-agent${NC}"
fi

# =============================================================================
# SET PERMISSIONS
# =============================================================================

chown -R root:root "${INSTALL_DIR}"
chmod -R 750 "${INSTALL_DIR}"
chmod 640 "${CONF_FILE}"
chmod -R 750 "${DATA_DIR}" "${LOG_DIR}"
chown -R root:root "${RUN_DIR}"
chmod 755 "${RUN_DIR}"

# Store API token securely
if [[ -n "${API_TOKEN:-}" ]]; then
    echo "${API_TOKEN}" > "${DATA_DIR}/api_token"
    chmod 600 "${DATA_DIR}/api_token"
fi

# Initialize default whitelist
source "${INSTALL_DIR}/lib/common.sh" 2>/dev/null || true
source "${INSTALL_DIR}/lib/whitelist.sh" 2>/dev/null || true
export OBSIDIAN_DATA="${DATA_DIR}"
whitelist_add_defaults 2>/dev/null || true

# =============================================================================
# DONE
# =============================================================================

echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Obsidian Security Suite installed successfully!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "    obsidian status              — Check system status"
echo -e "    obsidian health check        — Full health check"
echo -e "    obsidian malware scan        — Scan for malware"
echo -e "    obsidian bots analyze        — Analyze bot traffic"
echo -e "    obsidian ban 1.2.3.4         — Ban an IP"
echo -e "    obsidian scan baseline /var/www --preset wordpress"
echo ""
echo -e "  ${BOLD}Config:${NC} ${CONF_FILE}"
echo -e "  ${BOLD}Logs:${NC}   ${LOG_DIR}/obsidian.log"

if [[ -n "${API_TOKEN:-}" ]]; then
    echo ""
    echo -e "  ${YELLOW}${BOLD}IMPORTANT: Save your API token:${NC}"
    echo -e "  ${API_TOKEN}"
    echo -e "  ${YELLOW}You'll need this to configure agents on other servers.${NC}"
fi

echo ""
