#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Banner
# =============================================================================

show_banner() {
    local version="${OBSIDIAN_VERSION:-1.0.0}"
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
   ____  __         _     ___
  / __ \/ /_  _____(_)___/ (_)___ _____
 / / / / __ \/ ___/ / __  / / __ `/ __ \
/ /_/ / /_/ (__  ) / /_/ / / /_/ / / / /
\____/_.___/____/_/\__,_/_/\__,_/_/ /_/
BANNER
    echo -e "${NC}"
    echo -e "  ${WHITE}Server Security Suite${NC} ${CYAN}v${version}${NC}"
    echo -e "  ${BLUE}────────────────────────────────────${NC}"
    echo -e "  ${GREEN}Modules:${NC} Firewall · FileGuard · Malware"
    echo -e "           BotGuard · HealthCheck · Sync"
    echo -e "  ${BLUE}────────────────────────────────────${NC}\n"
}

show_mini_banner() {
    echo -e "${CYAN}${BOLD}Obsidian${NC} v${OBSIDIAN_VERSION:-1.0.0} — Server Security Suite"
}
