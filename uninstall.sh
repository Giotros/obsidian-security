#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Uninstaller
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="/opt/obsidian"

echo -e "\n${BOLD}Obsidian Security Suite — Uninstaller${NC}\n"

if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}This will remove Obsidian from your server.${NC}"
read -rp "Keep data files (bans, logs, config)? [Y/n]: " keep_data
keep_data="${keep_data:-Y}"

# Stop services
echo -e "\n${BOLD}Stopping services...${NC}"
systemctl stop obsidian-agent 2>/dev/null || true
systemctl disable obsidian-agent 2>/dev/null || true
rm -f /etc/systemd/system/obsidian-agent.service
systemctl daemon-reload 2>/dev/null || true
echo -e "  ${GREEN}✓ Service stopped and removed${NC}"

# Kill any running processes
pkill -f obsidian-agent 2>/dev/null || true
pkill -f obsidian-api 2>/dev/null || true

# Remove symlink
rm -f /usr/local/bin/obsidian
echo -e "  ${GREEN}✓ CLI symlink removed${NC}"

# Remove CGI
for cgi_dir in /usr/lib/cgi-bin /usr/local/cpanel/cgi-sys /var/www/cgi-bin; do
    rm -f "${cgi_dir}/obsidian-api.sh" 2>/dev/null || true
done
echo -e "  ${GREEN}✓ CGI endpoint removed${NC}"

# Remove files
if [[ "${keep_data}" =~ ^[nN] ]]; then
    rm -rf "${INSTALL_DIR}"
    rm -rf /var/run/obsidian
    echo -e "  ${GREEN}✓ All files removed (including data)${NC}"
else
    # Keep data, remove code
    rm -rf "${INSTALL_DIR}/lib" "${INSTALL_DIR}/agent" "${INSTALL_DIR}/server"
    rm -rf "${INSTALL_DIR}/rules" "${INSTALL_DIR}/presets"
    rm -f "${INSTALL_DIR}/obsidian" "${INSTALL_DIR}/install.sh" "${INSTALL_DIR}/uninstall.sh"
    echo -e "  ${GREEN}✓ Code removed, data preserved in ${INSTALL_DIR}/data${NC}"
fi

# Remove system user
if id obsidian &>/dev/null; then
    userdel obsidian 2>/dev/null || true
    echo -e "  ${GREEN}✓ System user removed${NC}"
fi

echo -e "\n${GREEN}${BOLD}Obsidian uninstalled successfully.${NC}\n"
