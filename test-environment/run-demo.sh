#!/bin/bash
# =============================================================================
# Obsidian Security Suite — Interactive Demo
# Walks through all modules with real (simulated) threats
# =============================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
    echo ""
}

step() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  STEP $1: $2${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${NC}\n"
}

echo -e "${BOLD}"
cat << 'BANNER'
   ____  __         _     ___
  / __ \/ /_  _____(_)___/ (_)___ _____
 / / / / __ \/ ___/ / __  / / __ `/ __ \
/ /_/ / /_/ (__  ) / /_/ / / /_/ / / / /
\____/_.___/____/_/\__,_/_/\__,_/_/ /_/

    S E C U R I T Y  — Interactive Demo
BANNER
echo -e "${NC}"

# Step 1: Status
step 1 "System Status Overview"
echo "Command: obsidian status"
pause
obsidian status

# Step 2: Health Check
step 2 "Full Health Check"
echo "Let's see how healthy this server is..."
echo "Command: obsidian health check"
pause
obsidian health check

# Step 3: Malware Scan
step 3 "Malware & Cryptominer Detection"
echo "There's a hidden cryptominer on this server."
echo "Location: /home/mybagonline/.config/.cache/fontconfig/lib-update"
echo "It was planted on Feb 27 and has a cron job restarting it every 2 hours."
echo ""
echo "Let's find it!"
echo "Command: obsidian malware scan /home"
pause
obsidian malware scan /home

# Step 4: Cron Audit
step 4 "Cron Job Audit (focused)"
echo "Let's specifically look at cron jobs..."
echo "Command: obsidian malware crons"
pause
obsidian malware crons

# Step 5: Bot Analysis
step 5 "Bot Traffic Analysis"
echo "The server is being hammered by aggressive bots at night."
echo "Let's analyze the access logs..."
echo "Command: obsidian bots analyze"
pause
obsidian bots analyze

# Step 6: Vulnerability Scanner Detection
step 6 "Vulnerability Scanner Detection"
echo "Someone is probing for .env files, wp-config backups, and using sqlmap..."
echo "Command: obsidian bots scanners"
pause
obsidian bots scanners

# Step 7: File Integrity
step 7 "File Integrity Scan"
echo "Let's check if any WordPress core files have been tampered with..."
echo "First, generate a baseline, then inject a change and detect it."
echo ""
echo "Command: obsidian scan baseline /var/www/html --preset wordpress"
pause
obsidian scan baseline /var/www/html --preset wordpress

echo ""
echo -e "${RED}Now simulating an attacker modifying wp-config.php...${NC}"
echo "HACKED_BY_ATTACKER=true" >> /var/www/html/wp-config.php
sleep 1

echo ""
echo "Command: obsidian scan full /var/www/html"
pause
obsidian scan full /var/www/html

# Step 8: IP Ban
step 8 "IP Ban Management"
echo "Let's ban the rate abuser (45.33.32.156 — 350 requests)..."
echo "Command: obsidian ban 45.33.32.156 --reason 'Rate abuse - 350 req/min' --by george"
pause
obsidian ban 45.33.32.156 --reason "Rate abuse - 350 req/min" --by george

echo ""
echo "And the vulnerability scanner..."
echo "Command: obsidian ban 185.220.101.42 --reason 'Nikto/sqlmap scanning' --by george"
obsidian ban 185.220.101.42 --reason "Nikto/sqlmap scanning" --by george

echo ""
echo "Command: obsidian ban list"
obsidian ban list

# Step 9: Whitelist
step 9 "Whitelist Management"
echo "Let's whitelist our internal network..."
echo "Command: obsidian whitelist add 192.168.1.0/24 --reason 'Office LAN'"
pause
obsidian whitelist add 192.168.1.0/24 --reason "Office LAN"
obsidian whitelist list

# Summary
echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Demo Complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
echo "  What Obsidian found on this server:"
echo "  ─────────────────────────────────"
echo -e "  ${RED}✗${NC} Hidden cryptominer in .config/.cache/fontconfig/"
echo -e "  ${RED}✗${NC} Malicious cron job (every 2 hours)"
echo -e "  ${RED}✗${NC} PHP web shell in wp-content/plugins/"
echo -e "  ${RED}✗${NC} Backdoor in /tmp/"
echo -e "  ${RED}✗${NC} 50+ Bytespider bot requests"
echo -e "  ${RED}✗${NC} 30+ AhrefsBot crawler requests"
echo -e "  ${RED}✗${NC} Nikto/sqlmap vulnerability scanning"
echo -e "  ${RED}✗${NC} 350 requests from rate abuser"
echo -e "  ${RED}✗${NC} Modified wp-config.php detected"
echo -e "  ${RED}✗${NC} World-writable PHP file"
echo ""
echo "  All from ONE tool: obsidian"
echo ""
