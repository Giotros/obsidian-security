#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — System Health Monitor
# Monitors: CPU, RAM, disk, PHP processes, system security status
#
# Born from real incident: PHP crashes from aggressive process recycling
# (extMaxIdleTime=10s), disk 90% full, PHP 7.4 EOL
# =============================================================================

readonly HEALTH_LOG="${OBSIDIAN_LOGS}/health.log"
readonly HEALTH_STATE="${OBSIDIAN_DATA}/health_state.txt"

# Thresholds (configurable via obsidian.conf)
CPU_WARN_THRESHOLD="${CPU_WARN_THRESHOLD:-80}"
CPU_CRIT_THRESHOLD="${CPU_CRIT_THRESHOLD:-95}"
MEM_WARN_THRESHOLD="${MEM_WARN_THRESHOLD:-80}"
MEM_CRIT_THRESHOLD="${MEM_CRIT_THRESHOLD:-95}"
DISK_WARN_THRESHOLD="${DISK_WARN_THRESHOLD:-80}"
DISK_CRIT_THRESHOLD="${DISK_CRIT_THRESHOLD:-90}"
PHP_MIN_IDLE_TIME="${PHP_MIN_IDLE_TIME:-30}"   # Alert if extMaxIdleTime < this
LOAD_WARN_MULTIPLIER="${LOAD_WARN_MULTIPLIER:-2}"  # Alert if load > cores * this

# =============================================================================
# CPU MONITORING
# =============================================================================

check_cpu() {
    local cpu_usage
    cpu_usage="$(top -bn1 | grep "Cpu(s)" | awk '{print 100 - $8}' 2>/dev/null || echo "0")"
    cpu_usage="${cpu_usage%.*}"  # Remove decimals

    local num_cores
    num_cores="$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo 2>/dev/null || echo 1)"

    local load_1 load_5 load_15
    read -r load_1 load_5 load_15 _ < /proc/loadavg 2>/dev/null || { load_1="0"; load_5="0"; load_15="0"; }

    local load_threshold
    load_threshold="$(echo "${num_cores} * ${LOAD_WARN_MULTIPLIER}" | bc 2>/dev/null || echo "${num_cores}")"

    print_row "CPU Usage" "${cpu_usage}%"
    print_row "CPU Cores" "${num_cores}"
    print_row "Load Average" "${load_1} / ${load_5} / ${load_15}"

    if [[ "${cpu_usage}" -ge "${CPU_CRIT_THRESHOLD}" ]]; then
        print_status "critical" "CPU critical: ${cpu_usage}% (threshold: ${CPU_CRIT_THRESHOLD}%)"
        send_alert "${SEVERITY_CRITICAL}" "Health" "CPU Critical" \
            "CPU usage at ${cpu_usage}%\nLoad: ${load_1}/${load_5}/${load_15}\nCores: ${num_cores}" &
        return 2
    elif [[ "${cpu_usage}" -ge "${CPU_WARN_THRESHOLD}" ]]; then
        print_status "warn" "CPU warning: ${cpu_usage}% (threshold: ${CPU_WARN_THRESHOLD}%)"
        return 1
    else
        print_status "ok" "CPU normal: ${cpu_usage}%"
        return 0
    fi
}

# =============================================================================
# MEMORY MONITORING
# =============================================================================

check_memory() {
    local mem_total mem_available mem_used mem_percent
    mem_total="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')"
    mem_available="$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}')"

    if [[ -z "${mem_total}" ]] || [[ "${mem_total}" -eq 0 ]]; then
        print_status "warn" "Cannot read memory info"
        return 1
    fi

    mem_used=$(( mem_total - mem_available ))
    mem_percent=$(( (mem_used * 100) / mem_total ))

    local mem_total_mb=$(( mem_total / 1024 ))
    local mem_used_mb=$(( mem_used / 1024 ))
    local mem_available_mb=$(( mem_available / 1024 ))

    # Swap info
    local swap_total swap_used swap_percent
    swap_total="$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2}')"
    swap_used=$(( swap_total - $(grep SwapFree /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0) ))
    if [[ "${swap_total}" -gt 0 ]]; then
        swap_percent=$(( (swap_used * 100) / swap_total ))
    else
        swap_percent=0
    fi

    print_row "Memory" "${mem_used_mb}MB / ${mem_total_mb}MB (${mem_percent}%)"
    print_row "Available" "${mem_available_mb}MB"
    print_row "Swap" "$(( swap_used / 1024 ))MB / $(( swap_total / 1024 ))MB (${swap_percent}%)"

    if [[ "${mem_percent}" -ge "${MEM_CRIT_THRESHOLD}" ]]; then
        print_status "critical" "Memory critical: ${mem_percent}%"
        send_alert "${SEVERITY_CRITICAL}" "Health" "Memory Critical" \
            "Memory usage at ${mem_percent}%\nUsed: ${mem_used_mb}MB / ${mem_total_mb}MB\nSwap: ${swap_percent}%" &
        return 2
    elif [[ "${mem_percent}" -ge "${MEM_WARN_THRESHOLD}" ]]; then
        print_status "warn" "Memory warning: ${mem_percent}%"
        return 1
    else
        print_status "ok" "Memory normal: ${mem_percent}%"
        return 0
    fi
}

# =============================================================================
# DISK MONITORING
# =============================================================================

check_disk() {
    local issues=0

    # Check all mounted filesystems (skip virtual/temp)
    while IFS= read -r line; do
        local filesystem mountpoint size used available percent
        filesystem="$(echo "${line}" | awk '{print $1}')"
        size="$(echo "${line}" | awk '{print $2}')"
        used="$(echo "${line}" | awk '{print $3}')"
        available="$(echo "${line}" | awk '{print $4}')"
        percent="$(echo "${line}" | awk '{print $5}' | tr -d '%')"
        mountpoint="$(echo "${line}" | awk '{print $6}')"

        # Skip small/virtual filesystems
        [[ "${size}" == "0" ]] && continue

        print_row "Disk ${mountpoint}" "${used} / ${size} (${percent}%)"

        if [[ "${percent}" -ge "${DISK_CRIT_THRESHOLD}" ]]; then
            print_status "critical" "Disk ${mountpoint}: ${percent}% full (available: ${available})"
            send_alert "${SEVERITY_CRITICAL}" "Health" "Disk Space Critical" \
                "Disk ${mountpoint} at ${percent}%\nUsed: ${used} / ${size}\nAvailable: ${available}" &
            issues=$(( issues + 2 ))
        elif [[ "${percent}" -ge "${DISK_WARN_THRESHOLD}" ]]; then
            print_status "warn" "Disk ${mountpoint}: ${percent}% (available: ${available})"
            issues=$(( issues + 1 ))
        else
            print_status "ok" "Disk ${mountpoint}: ${percent}%"
        fi
    done < <(df -h --output=source,size,used,avail,pcent,target 2>/dev/null | grep '^/' | grep -v '/dev/loop\|tmpfs\|devtmpfs')

    # Check inode usage
    local inode_percent
    inode_percent="$(df -i / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')"
    if [[ -n "${inode_percent}" ]] && [[ "${inode_percent}" -ge 80 ]]; then
        print_status "warn" "Inode usage: ${inode_percent}% — may prevent creating new files"
        issues=$(( issues + 1 ))
    fi

    return "${issues}"
}

# =============================================================================
# PHP PROCESS MONITORING
# =============================================================================

check_php() {
    local issues=0

    # Detect PHP version
    local php_version
    php_version="$(detect_php)"

    if [[ "${php_version}" == "not_found" ]]; then
        print_status "info" "PHP not detected"
        return 0
    fi

    print_row "PHP Version" "${php_version}"

    # Check for EOL PHP versions
    local major_minor="${php_version%.*}"
    case "${major_minor}" in
        7.4|7.3|7.2|7.1|7.0|5.*)
            print_status "critical" "PHP ${major_minor} is END OF LIFE — upgrade immediately!"
            send_alert "${SEVERITY_HIGH}" "Health" "PHP EOL" \
                "PHP ${php_version} is end-of-life.\nNo security patches available.\nUpgrade to PHP 8.1+ recommended." &
            issues=$(( issues + 1 ))
            ;;
        8.0)
            print_status "warn" "PHP 8.0 is EOL — consider upgrading to 8.1+"
            issues=$(( issues + 1 ))
            ;;
        8.1|8.2|8.3|8.4)
            print_status "ok" "PHP ${major_minor} is supported"
            ;;
    esac

    # Count PHP processes
    local php_procs
    php_procs="$(pgrep -c 'php-fpm\|php-cgi\|lsphp' 2>/dev/null || echo 0)"
    print_row "PHP Processes" "${php_procs}"

    # Check for PHP-FPM/LSAPI configuration issues
    check_php_config issues

    # Check for zombie PHP processes
    local zombie_php
    zombie_php="$(ps aux 2>/dev/null | awk '$8 ~ /Z/ && /php/ {count++} END {print count+0}')"
    if [[ "${zombie_php}" -gt 0 ]]; then
        print_status "warn" "${zombie_php} zombie PHP process(es) detected"
        issues=$(( issues + 1 ))
    fi

    # Check for long-running PHP processes (over 5 minutes)
    local long_running=0
    while IFS= read -r line; do
        local pid etime
        pid="$(echo "${line}" | awk '{print $1}')"
        etime="$(echo "${line}" | awk '{print $2}')"

        # etime format: [[DD-]HH:]MM:SS
        if echo "${etime}" | grep -qE '^[0-9]+-|^[0-9]+:[0-9]+:[0-9]+'; then
            long_running=$(( long_running + 1 ))
        fi
    done < <(ps -eo pid,etime,comm 2>/dev/null | grep -E 'php-fpm|php-cgi|lsphp' | grep -v grep)

    if [[ "${long_running}" -gt 0 ]]; then
        print_status "warn" "${long_running} long-running PHP process(es) (>5 min)"
        issues=$(( issues + 1 ))
    fi

    return "${issues}"
}

check_php_config() {
    local -n issues_ref=$1

    # Check PHP-FPM pool configs for aggressive recycling
    local -a fpm_configs=()
    for conf in /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf; do
        [[ -f "${conf}" ]] && fpm_configs+=("${conf}")
    done

    for conf in "${fpm_configs[@]}"; do
        # Check pm.max_requests (too low causes frequent recycling)
        local max_requests
        max_requests="$(grep -oP '^pm\.max_requests\s*=\s*\K\d+' "${conf}" 2>/dev/null || echo "")"
        if [[ -n "${max_requests}" ]] && [[ "${max_requests}" -lt 100 ]] && [[ "${max_requests}" -gt 0 ]]; then
            print_status "warn" "$(basename "${conf}"): pm.max_requests=${max_requests} (too low, recommend 500+)"
            issues_ref=$(( issues_ref + 1 ))
        fi

        # Check pm.max_children
        local max_children
        max_children="$(grep -oP '^pm\.max_children\s*=\s*\K\d+' "${conf}" 2>/dev/null || echo "")"
        if [[ -n "${max_children}" ]] && [[ "${max_children}" -lt 5 ]]; then
            print_status "warn" "$(basename "${conf}"): pm.max_children=${max_children} (too low for production)"
            issues_ref=$(( issues_ref + 1 ))
        fi
    done

    # Check LSAPI/LiteSpeed settings (common on cPanel)
    if [[ -f "/usr/local/lsws/conf/httpd_config.xml" ]]; then
        local idle_time
        idle_time="$(grep -oP 'extMaxIdleTime>\K[0-9]+' /usr/local/lsws/conf/httpd_config.xml 2>/dev/null || echo "")"
        if [[ -n "${idle_time}" ]] && [[ "${idle_time}" -lt "${PHP_MIN_IDLE_TIME}" ]]; then
            print_status "critical" "LSAPI extMaxIdleTime=${idle_time}s — TOO LOW (causes PHP crashes!)"
            print_status "info" "Recommendation: Set extMaxIdleTime to 60-300 seconds"
            send_alert "${SEVERITY_HIGH}" "Health" "PHP Config Issue" \
                "extMaxIdleTime=${idle_time}s is causing PHP process recycling too aggressively.\nThis leads to 503 errors.\nRecommendation: Raise to 60-300 seconds." &
            issues_ref=$(( issues_ref + 1 ))
        fi
    fi

    # Check CloudLinux LVE limits (common on cPanel shared hosting)
    if command -v lvectl &>/dev/null; then
        print_status "info" "CloudLinux detected — checking LVE limits"
        local lve_faults
        lve_faults="$(lvectl list-faults 2>/dev/null | wc -l || echo 0)"
        if [[ "${lve_faults}" -gt 1 ]]; then
            print_status "warn" "CloudLinux LVE: ${lve_faults} resource faults detected"
            issues_ref=$(( issues_ref + 1 ))
        fi
    fi
}

# =============================================================================
# NETWORK CONNECTION ANALYSIS
# =============================================================================

check_connections() {
    local issues=0

    # Total connections
    local total_conn
    total_conn="$(ss -s 2>/dev/null | grep 'TCP:' | grep -oP '\d+ estab' | grep -oP '^\d+')"
    total_conn="${total_conn:-0}"
    print_row "TCP Established" "${total_conn}"

    # Connections per IP (top offenders)
    local top_ips
    top_ips="$(ss -tn state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5)"

    if [[ -n "${top_ips}" ]]; then
        print_row "Top Connectors" ""
        while IFS= read -r line; do
            local count ip
            count="$(echo "${line}" | awk '{print $1}')"
            ip="$(echo "${line}" | awk '{print $2}')"
            [[ -z "${ip}" ]] && continue
            if [[ "${count}" -gt 100 ]]; then
                echo -e "    ${RED}${count}${NC} connections from ${ip}"
                issues=$(( issues + 1 ))
            elif [[ "${count}" -gt 50 ]]; then
                echo -e "    ${YELLOW}${count}${NC} connections from ${ip}"
            else
                echo "    ${count} connections from ${ip}"
            fi
        done <<< "${top_ips}"
    fi

    # Check for SYN flood indicators
    local syn_recv
    syn_recv="$(ss -s 2>/dev/null | grep 'synrecv' | grep -oP '\d+' | head -1)"
    syn_recv="${syn_recv:-0}"
    if [[ "${syn_recv}" -gt 100 ]]; then
        print_status "critical" "Possible SYN flood: ${syn_recv} half-open connections"
        send_alert "${SEVERITY_CRITICAL}" "Health" "SYN Flood Detected" \
            "Half-open connections: ${syn_recv}\nThis may indicate a SYN flood attack." &
        issues=$(( issues + 1 ))
    fi

    # TIME_WAIT connections (indicates recent heavy traffic)
    local time_wait
    time_wait="$(ss -s 2>/dev/null | grep 'timewait' | grep -oP '\d+' | head -1)"
    time_wait="${time_wait:-0}"
    if [[ "${time_wait}" -gt 1000 ]]; then
        print_status "warn" "High TIME_WAIT: ${time_wait} (heavy recent traffic)"
    fi

    return "${issues}"
}

# =============================================================================
# SECURITY POSTURE CHECK
# =============================================================================

check_security_posture() {
    local issues=0

    print_header "Security Posture"

    # Firewall status
    local firewall
    firewall="$(detect_firewall)"
    if [[ "${firewall}" == "none" ]]; then
        print_status "critical" "No firewall detected!"
        issues=$(( issues + 1 ))
    else
        print_status "ok" "Firewall: ${firewall}"
    fi

    # SSH config checks
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        local root_login
        root_login="$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
        if [[ "${root_login}" == "yes" ]]; then
            print_status "warn" "SSH: Root login enabled — consider disabling"
            issues=$(( issues + 1 ))
        else
            print_status "ok" "SSH: Root login disabled"
        fi

        local password_auth
        password_auth="$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
        if [[ "${password_auth}" == "yes" ]]; then
            print_status "warn" "SSH: Password auth enabled — consider key-only"
        else
            print_status "ok" "SSH: Password auth disabled"
        fi
    fi

    # Check for pending security updates
    if command -v apt &>/dev/null; then
        local security_updates
        security_updates="$(apt list --upgradable 2>/dev/null | grep -c security 2>/dev/null || true)"
        security_updates="${security_updates:-0}"
        security_updates="$(echo "${security_updates}" | tr -d '[:space:]')"
        if [[ "${security_updates}" -gt 0 ]]; then
            print_status "warn" "${security_updates} security update(s) pending"
            issues=$(( issues + 1 ))
        else
            print_status "ok" "System packages up to date"
        fi
    fi

    # Check fail2ban
    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            print_status "ok" "Fail2ban: active"
        else
            print_status "warn" "Fail2ban: installed but not running"
            issues=$(( issues + 1 ))
        fi
    fi

    # World-writable directories in web root
    local www_writable
    www_writable="$(find /var/www /home/*/public_html -type d -perm -o+w 2>/dev/null | wc -l | tr -d '[:space:]')"
    www_writable="${www_writable:-0}"
    if [[ "${www_writable}" -gt 0 ]]; then
        print_status "warn" "${www_writable} world-writable web directories"
        issues=$(( issues + 1 ))
    fi

    return "${issues}"
}

# =============================================================================
# FULL HEALTH CHECK
# =============================================================================

full_health_check() {
    print_header "Obsidian System Health Check"
    print_row "Server" "$(hostname -f 2>/dev/null || hostname)"
    print_row "Uptime" "$(uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')"
    print_row "Timestamp" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    local total_issues=0

    echo -e "\n${BOLD}[1/5] CPU & Load${NC}"
    local cpu_issues=0
    check_cpu || cpu_issues=$?
    total_issues=$(( total_issues + cpu_issues ))

    echo -e "\n${BOLD}[2/5] Memory${NC}"
    local mem_issues=0
    check_memory || mem_issues=$?
    total_issues=$(( total_issues + mem_issues ))

    echo -e "\n${BOLD}[3/5] Disk Space${NC}"
    local disk_issues=0
    check_disk || disk_issues=$?
    total_issues=$(( total_issues + disk_issues ))

    echo -e "\n${BOLD}[4/5] PHP & Web Server${NC}"
    local php_issues=0
    check_php || php_issues=$?
    total_issues=$(( total_issues + php_issues ))

    echo -e "\n${BOLD}[5/5] Network Connections${NC}"
    local net_issues=0
    check_connections || net_issues=$?
    total_issues=$(( total_issues + net_issues ))

    # Security posture
    check_security_posture || total_issues=$(( total_issues + $? ))

    # Summary
    echo ""
    print_header "Health Summary"
    local health_grade
    if [[ "${total_issues}" -eq 0 ]]; then
        health_grade="${GREEN}HEALTHY${NC}"
    elif [[ "${total_issues}" -le 3 ]]; then
        health_grade="${YELLOW}ATTENTION NEEDED${NC}"
    else
        health_grade="${RED}CRITICAL${NC}"
    fi
    echo -e "  System Status: ${BOLD}${health_grade}${NC}"
    echo -e "  Issues Found: ${total_issues}"

    # Log health check
    echo "$(date '+%Y-%m-%d %H:%M:%S')|HEALTH_CHECK|issues=${total_issues}" >> "${HEALTH_LOG}" 2>/dev/null

    return "${total_issues}"
}
