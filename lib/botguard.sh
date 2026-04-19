#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — BotGuard Module
# Detects and blocks malicious bots, aggressive crawlers, and scanners
# Analyzes access logs for: bad User-Agents, request rate abuse,
# vulnerability scanning patterns, and known bad bot signatures
#
# Born from real issue: Bytespider, generic scanners, Facebook crawlers
# hammering sites during vulnerable night hours
# =============================================================================

readonly BAD_BOTS_FILE="${OBSIDIAN_DIR}/rules/bad-bots.txt"
readonly BOTGUARD_LOG="${OBSIDIAN_LOGS}/botguard.log"
readonly BOTGUARD_STATE="${OBSIDIAN_DATA}/botguard_state.txt"

# Rate limiting thresholds
RATE_WINDOW="${RATE_WINDOW:-60}"           # seconds
RATE_MAX_REQUESTS="${RATE_MAX_REQUESTS:-120}"  # max requests per window
RATE_BAN_THRESHOLD="${RATE_BAN_THRESHOLD:-300}" # auto-ban above this

# =============================================================================
# ACCESS LOG ANALYSIS — Find abusive IPs by request rate
# =============================================================================

analyze_request_rates() {
    local log_file="${1:-}"
    local window="${2:-${RATE_WINDOW}}"
    local threshold="${3:-${RATE_MAX_REQUESTS}}"

    # Auto-detect log file if not specified
    if [[ -z "${log_file}" ]]; then
        for path in \
            /var/log/apache2/access.log \
            /var/log/httpd/access_log \
            /usr/local/apache/logs/access_log \
            /var/log/nginx/access.log; do
            [[ -f "${path}" ]] && log_file="${path}" && break
        done
    fi

    if [[ -z "${log_file}" ]] || [[ ! -f "${log_file}" ]]; then
        log_error "No access log found"
        return 1
    fi

    log_info "Analyzing request rates from: ${log_file}"

    local now
    now="$(date +%s)"
    local window_start=$(( now - window ))

    # Extract IPs and count requests in the time window
    declare -A ip_counts
    declare -A ip_last_ua

    while IFS= read -r line; do
        local ip
        ip="$(echo "${line}" | awk '{print $1}')"
        validate_ip "${ip}" || continue

        # Parse timestamp
        local log_time
        log_time="$(echo "${line}" | grep -oP '\[\K[^\]]+' | head -1)"
        local log_epoch
        log_epoch="$(date -d "$(echo "${log_time}" | sed 's/:/ /' | sed 's/\+/ +/')" +%s 2>/dev/null || echo 0)"

        if [[ "${log_epoch}" -ge "${window_start}" ]]; then
            ip_counts["${ip}"]=$(( ${ip_counts["${ip}"]:-0} + 1 ))

            # Capture User-Agent
            local ua
            ua="$(echo "${line}" | grep -oP '"[^"]*"$' | tr -d '"')"
            [[ -n "${ua}" ]] && ip_last_ua["${ip}"]="${ua}"
        fi
    done < <(tail -10000 "${log_file}" 2>/dev/null)

    # Report results
    local abusive_count=0

    print_header "Request Rate Analysis (last ${window}s)"
    printf "  ${BOLD}%-18s %-8s %-10s %s${NC}\n" "IP" "REQS" "STATUS" "USER-AGENT"
    print_separator 90

    # Sort by request count (descending)
    for ip in $(for k in "${!ip_counts[@]}"; do echo "${ip_counts[$k]} $k"; done | sort -rn | awk '{print $2}' | head -30); do
        local count="${ip_counts[${ip}]}"
        local ua="${ip_last_ua[${ip}]:-unknown}"
        local status="ok"
        local color="${GREEN}"

        if [[ "${count}" -ge "${RATE_BAN_THRESHOLD}" ]]; then
            status="BAN"
            color="${RED}"
            abusive_count=$(( abusive_count + 1 ))
        elif [[ "${count}" -ge "${threshold}" ]]; then
            status="WARN"
            color="${YELLOW}"
            abusive_count=$(( abusive_count + 1 ))
        fi

        if [[ "${count}" -ge "${threshold}" ]]; then
            printf "  %-18s ${color}%-8s %-10s${NC} %s\n" "${ip}" "${count}" "${status}" "${ua:0:45}"
        fi
    done

    if [[ "${abusive_count}" -eq 0 ]]; then
        print_status "ok" "No rate abuse detected"
    fi

    return "${abusive_count}"
}

# =============================================================================
# USER-AGENT SCANNER — Detect known bad bots
# =============================================================================

scan_user_agents() {
    local log_file="${1:-}"

    # Auto-detect log file
    if [[ -z "${log_file}" ]]; then
        for path in \
            /var/log/apache2/access.log \
            /var/log/httpd/access_log \
            /usr/local/apache/logs/access_log \
            /var/log/nginx/access.log; do
            [[ -f "${path}" ]] && log_file="${path}" && break
        done
    fi

    if [[ -z "${log_file}" ]] || [[ ! -f "${log_file}" ]]; then
        log_error "No access log found"
        return 1
    fi

    log_info "Scanning User-Agents in: ${log_file}"

    # Load bad bot patterns
    local -a bad_patterns=()
    if [[ -f "${BAD_BOTS_FILE}" ]]; then
        while IFS= read -r pattern; do
            [[ -z "${pattern}" ]] && continue
            [[ "${pattern}" =~ ^# ]] && continue
            bad_patterns+=("${pattern}")
        done < "${BAD_BOTS_FILE}"
    fi

    # Built-in bad bot patterns (always checked)
    bad_patterns+=(
        "Bytespider"
        "AhrefsBot"
        "SemrushBot"
        "MJ12bot"
        "DotBot"
        "PetalBot"
        "YandexBot"
        "BLEXBot"
        "DataForSeoBot"
        "GPTBot"
        "CCBot"
        "Sogou"
        "zgrab"
        "masscan"
        "Nuclei"
        "nikto"
        "sqlmap"
        "nmap"
        "dirbuster"
        "gobuster"
        "wpscan"
        "joomla.*scanner"
        "python-requests"
        "Go-http-client"
        "curl/"
        "wget/"
        "libwww-perl"
        "PhantomJS"
        "HeadlessChrome"
    )

    declare -A bot_ips
    declare -A bot_counts
    declare -A bot_ua

    # Scan log for bad User-Agents
    for pattern in "${bad_patterns[@]}"; do
        while IFS= read -r line; do
            local ip
            ip="$(echo "${line}" | awk '{print $1}')"
            validate_ip "${ip}" || continue

            bot_ips["${ip}"]=1
            bot_counts["${ip}"]=$(( ${bot_counts["${ip}"]:-0} + 1 ))
            bot_ua["${ip}"]="${pattern}"
        done < <(grep -i "${pattern}" "${log_file}" 2>/dev/null | tail -500)
    done

    # Report
    local found=${#bot_ips[@]}

    print_header "Bad Bot Detection"
    if [[ "${found}" -gt 0 ]]; then
        printf "  ${BOLD}%-18s %-8s %s${NC}\n" "IP" "HITS" "MATCHED PATTERN"
        print_separator 60

        for ip in $(for k in "${!bot_counts[@]}"; do echo "${bot_counts[$k]} $k"; done | sort -rn | awk '{print $2}' | head -20); do
            local count="${bot_counts[${ip}]}"
            local ua="${bot_ua[${ip}]}"
            printf "  ${RED}%-18s${NC} %-8s %s\n" "${ip}" "${count}" "${ua}"
        done
        echo ""
        print_status "warn" "${found} bad bot IP(s) detected"
    else
        print_status "ok" "No known bad bots detected in recent logs"
    fi

    return "${found}"
}

# =============================================================================
# VULNERABILITY SCANNER DETECTION
# =============================================================================

detect_scanners() {
    local log_file="${1:-}"

    # Auto-detect
    if [[ -z "${log_file}" ]]; then
        for path in \
            /var/log/apache2/access.log \
            /var/log/httpd/access_log \
            /usr/local/apache/logs/access_log; do
            [[ -f "${path}" ]] && log_file="${path}" && break
        done
    fi

    [[ -z "${log_file}" ]] || [[ ! -f "${log_file}" ]] && return 1

    log_info "Detecting vulnerability scanners in: ${log_file}"

    # Patterns that indicate vulnerability scanning
    local -a scan_patterns=(
        'wp-login\.php.*POST'          # WordPress brute force
        'xmlrpc\.php.*POST'            # XML-RPC abuse
        '/\.env'                       # Environment file probing
        '/\.git/'                      # Git directory probing
        '/wp-config\.php\.bak'         # Config backup probing
        '/phpmyadmin'                  # phpMyAdmin probing
        '/admin.*\.php'                # Admin panel probing
        '/shell\|/cmd\|/backdoor'      # Backdoor probing
        '/etc/passwd'                  # Path traversal attempt
        '\.\./'                        # Directory traversal
        'UNION.*SELECT'               # SQL injection attempt
        '<script>'                    # XSS attempt
        '/wp-content/debug\.log'       # Debug log probing
        '/\.well-known/security\.txt'  # Security.txt probing
    )

    declare -A scanner_ips
    declare -A scanner_patterns

    for pattern in "${scan_patterns[@]}"; do
        while IFS= read -r line; do
            local ip
            ip="$(echo "${line}" | awk '{print $1}')"
            validate_ip "${ip}" || continue

            scanner_ips["${ip}"]=$(( ${scanner_ips["${ip}"]:-0} + 1 ))
            scanner_patterns["${ip}"]="${scanner_patterns["${ip}"]:-}${pattern%%\\*} "
        done < <(grep -iE "${pattern}" "${log_file}" 2>/dev/null | tail -200)
    done

    local found=${#scanner_ips[@]}

    print_header "Vulnerability Scanner Detection"
    if [[ "${found}" -gt 0 ]]; then
        printf "  ${BOLD}%-18s %-8s %s${NC}\n" "IP" "HITS" "PATTERNS"
        print_separator 70

        for ip in $(for k in "${!scanner_ips[@]}"; do echo "${scanner_ips[$k]} $k"; done | sort -rn | awk '{print $2}' | head -20); do
            local count="${scanner_ips[${ip}]}"
            local patterns="${scanner_patterns[${ip}]}"
            printf "  ${RED}%-18s${NC} %-8s %s\n" "${ip}" "${count}" "${patterns:0:45}"
        done
        echo ""
        print_status "warn" "${found} scanning IP(s) detected"
    else
        print_status "ok" "No vulnerability scanning detected"
    fi

    return "${found}"
}

# =============================================================================
# AUTO-BAN BOT IPs
# =============================================================================

auto_ban_bots() {
    local log_file="${1:-}"
    local dry_run="${2:-false}"

    log_info "Running auto-ban analysis for bots..."

    # Auto-detect log file if not provided
    if [[ -z "${log_file}" ]]; then
        for path in \
            /var/log/apache2/access.log \
            /var/log/httpd/access_log \
            /usr/local/apache/logs/access_log \
            /var/log/nginx/access.log; do
            [[ -f "${path}" ]] && log_file="${path}" && break
        done
    fi

    if [[ -z "${log_file}" ]] || [[ ! -f "${log_file}" ]]; then
        log_error "No access log found"
        return 1
    fi

    # Collect IPs from all detection methods
    declare -A ban_candidates
    declare -A ban_reasons

    # --- Method 1: Rate abuse ---
    declare -A rate_counts
    while IFS= read -r line; do
        local ip
        ip="$(echo "${line}" | awk '{print $1}')"
        validate_ip "${ip}" || continue
        rate_counts["${ip}"]=$(( ${rate_counts["${ip}"]:-0} + 1 ))
    done < <(tail -5000 "${log_file}" 2>/dev/null)

    for ip in "${!rate_counts[@]}"; do
        if [[ "${rate_counts[${ip}]}" -ge "${RATE_BAN_THRESHOLD}" ]]; then
            ban_candidates["${ip}"]=1
            ban_reasons["${ip}"]="Rate abuse: ${rate_counts[${ip}]} requests"
        fi
    done

    # --- Method 2: Bad bot User-Agents ---
    local -a bad_patterns=()
    if [[ -f "${BAD_BOTS_FILE}" ]]; then
        while IFS= read -r pattern; do
            [[ -z "${pattern}" ]] && continue
            [[ "${pattern}" =~ ^# ]] && continue
            bad_patterns+=("${pattern}")
        done < "${BAD_BOTS_FILE}"
    fi
    bad_patterns+=(
        "Bytespider" "AhrefsBot" "SemrushBot" "MJ12bot" "DotBot"
        "PetalBot" "YandexBot" "BLEXBot" "DataForSeoBot" "GPTBot" "CCBot"
        "zgrab" "masscan" "Nuclei" "nikto" "sqlmap" "nmap"
        "dirbuster" "gobuster" "wpscan" "python-requests" "Go-http-client"
        "libwww-perl" "PhantomJS" "HeadlessChrome"
    )

    for pattern in "${bad_patterns[@]}"; do
        while IFS= read -r line; do
            local ip
            ip="$(echo "${line}" | awk '{print $1}')"
            validate_ip "${ip}" || continue
            if [[ -z "${ban_candidates[${ip}]+x}" ]]; then
                ban_candidates["${ip}"]=1
                ban_reasons["${ip}"]="Bad bot UA: ${pattern}"
            fi
        done < <(grep -i "${pattern}" "${log_file}" 2>/dev/null | awk '{print $1}' | sort -u | while read -r uip; do grep -m1 "^${uip} " "${log_file}"; done)
    done

    # --- Method 3: Vulnerability scanners ---
    local -a scanner_paths=( "/.env" "/wp-config.php.bak" "/wp-config.php~"
        "/.git/config" "/phpinfo.php" "/admin/config" "/wp-login.php"
        "/xmlrpc.php" "/.aws/credentials" "/server-status" "/debug" )
    declare -A scanner_counts
    for spath in "${scanner_paths[@]}"; do
        while IFS= read -r ip; do
            validate_ip "${ip}" || continue
            scanner_counts["${ip}"]=$(( ${scanner_counts["${ip}"]:-0} + 1 ))
        done < <(grep "\"[A-Z]\\+ ${spath}" "${log_file}" 2>/dev/null | awk '{print $1}')
    done
    for ip in "${!scanner_counts[@]}"; do
        if [[ "${scanner_counts[${ip}]}" -ge 3 ]]; then
            if [[ -z "${ban_candidates[${ip}]+x}" ]]; then
                ban_candidates["${ip}"]=1
                ban_reasons["${ip}"]="Vuln scanner: ${scanner_counts[${ip}]} probe paths"
            fi
        fi
    done

    # --- Apply bans ---
    local banned=0
    local skipped=0
    for ip in "${!ban_candidates[@]}"; do
        # Skip whitelisted
        if is_whitelisted "${ip}"; then
            log_debug "Skipping whitelisted IP: ${ip}"
            skipped=$(( skipped + 1 ))
            continue
        fi

        # Skip already banned
        if is_banned "${ip}"; then
            skipped=$(( skipped + 1 ))
            continue
        fi

        if [[ "${dry_run}" == "true" ]]; then
            print_status "info" "Would ban: ${ip} — ${ban_reasons[${ip}]}"
        else
            if ban_ip "${ip}" "${ban_reasons[${ip}]}" "botguard" "botguard"; then
                banned=$(( banned + 1 ))
                print_status "ok" "Banned: ${ip} — ${ban_reasons[${ip}]}"
            fi
        fi
    done

    echo ""
    if [[ "${dry_run}" == "true" ]]; then
        echo -e "  ${YELLOW}Dry run — no bans applied. Remove --dry-run to execute.${NC}"
    else
        echo -e "  Bots banned: ${BOLD}${banned}${NC}"
        [[ "${skipped}" -gt 0 ]] && echo -e "  Skipped (whitelisted/already banned): ${skipped}"
    fi
}

# =============================================================================
# GENERATE .HTACCESS BOT BLOCKING RULES
# =============================================================================

generate_htaccess_rules() {
    print_header "Recommended .htaccess Bot Blocking Rules"
    echo ""
    echo "  Add these to your .htaccess file:"
    echo ""

    cat << 'HTACCESS'
    # === Obsidian BotGuard — Generated Rules ===
    # Block known bad bots by User-Agent
    <IfModule mod_rewrite.c>
        RewriteEngine On

        # Aggressive SEO/Scraper bots
        RewriteCond %{HTTP_USER_AGENT} (Bytespider|AhrefsBot|SemrushBot|MJ12bot|DotBot) [NC,OR]
        RewriteCond %{HTTP_USER_AGENT} (PetalBot|BLEXBot|DataForSeoBot|Sogou) [NC,OR]

        # Vulnerability scanners
        RewriteCond %{HTTP_USER_AGENT} (nikto|sqlmap|nmap|masscan|zgrab|Nuclei) [NC,OR]
        RewriteCond %{HTTP_USER_AGENT} (dirbuster|gobuster|wpscan) [NC,OR]

        # Generic/suspicious clients
        RewriteCond %{HTTP_USER_AGENT} (python-requests|Go-http-client|libwww-perl) [NC,OR]
        RewriteCond %{HTTP_USER_AGENT} (curl/|wget/) [NC]
        RewriteRule .* - [F,L]

        # Block XML-RPC (common attack vector)
        RewriteRule ^xmlrpc\.php$ - [F,L]
    </IfModule>

    # Rate limit wp-login.php
    <Files wp-login.php>
        <IfModule mod_rewrite.c>
            RewriteEngine On
            RewriteCond %{REQUEST_METHOD} POST
            RewriteCond %{HTTP_REFERER} !^https?://(www\.)?yourdomain\.com [NC]
            RewriteRule .* - [F,L]
        </IfModule>
    </Files>
    # === End Obsidian BotGuard Rules ===
HTACCESS

    echo ""
    echo -e "  ${YELLOW}Note: Replace 'yourdomain.com' with your actual domain.${NC}"
}

# =============================================================================
# FULL BOT ANALYSIS (combines all methods)
# =============================================================================

full_bot_analysis() {
    local log_file="${1:-}"

    print_header "Obsidian BotGuard — Full Analysis"
    print_row "Timestamp" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    local total_threats=0

    echo -e "\n${BOLD}[1/3] Request Rate Analysis${NC}"
    local rate_threats=0
    analyze_request_rates "${log_file}" || rate_threats=$?
    total_threats=$(( total_threats + rate_threats ))

    echo -e "\n${BOLD}[2/3] Bad Bot Detection${NC}"
    local bot_threats=0
    scan_user_agents "${log_file}" || bot_threats=$?
    total_threats=$(( total_threats + bot_threats ))

    echo -e "\n${BOLD}[3/3] Vulnerability Scanner Detection${NC}"
    local scan_threats=0
    detect_scanners "${log_file}" || scan_threats=$?
    total_threats=$(( total_threats + scan_threats ))

    echo ""
    print_header "BotGuard Summary"
    print_row "Rate abusers" "${rate_threats}"
    print_row "Bad bots" "${bot_threats}"
    print_row "Scanners" "${scan_threats}"
    print_separator
    if [[ "${total_threats}" -eq 0 ]]; then
        print_status "ok" "No bot threats detected"
    else
        print_status "warn" "${total_threats} threat(s) — consider running 'obsidian bots --auto-ban'"
    fi
}
