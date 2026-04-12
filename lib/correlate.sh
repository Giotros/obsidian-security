#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — IP Correlation Engine
# Cross-references file changes with access logs to identify responsible IPs
# Checks: Apache, FTP, SSH, cPanel file manager logs
# =============================================================================

# Time window for correlation (seconds before file change)
CORRELATE_WINDOW="${CORRELATE_WINDOW:-300}"  # 5 minutes

# Confidence thresholds
readonly CONFIDENCE_HIGH=80
readonly CONFIDENCE_MEDIUM=50
readonly CONFIDENCE_LOW=25

# =============================================================================
# MAIN CORRELATION FUNCTION
# =============================================================================

correlate_ip() {
    local filepath="$1"
    local change_time="$2"  # format: "YYYY-MM-DD HH:MM:SS" or epoch

    # Convert to epoch if needed
    local change_epoch
    if [[ "${change_time}" =~ ^[0-9]+$ ]]; then
        change_epoch="${change_time}"
    else
        change_epoch="$(date -d "${change_time}" +%s 2>/dev/null || echo 0)"
    fi

    local window_start=$(( change_epoch - CORRELATE_WINDOW ))

    # Collect candidates from all sources
    declare -A ip_scores
    declare -A ip_sources

    # Source 1: Apache/Nginx access logs
    check_web_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources

    # Source 2: FTP transfer logs
    check_ftp_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources

    # Source 3: SSH auth logs
    check_ssh_logs "${window_start}" "${change_epoch}" ip_scores ip_sources

    # Source 4: cPanel file manager logs
    check_cpanel_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources

    # Find the highest-scoring IP
    local best_ip=""
    local best_score=0

    for ip in "${!ip_scores[@]}"; do
        if [[ "${ip_scores[${ip}]}" -gt "${best_score}" ]]; then
            best_score="${ip_scores[${ip}]}"
            best_ip="${ip}"
        fi
    done

    if [[ -n "${best_ip}" ]] && [[ "${best_score}" -ge "${CONFIDENCE_LOW}" ]]; then
        echo "${best_ip}"
        log_debug "Correlated IP: ${best_ip} (score: ${best_score}, sources: ${ip_sources[${best_ip}]:-unknown})"
    fi
}

# Full correlation with detailed report
correlate_ip_detailed() {
    local filepath="$1"
    local change_time="$2"

    local change_epoch
    if [[ "${change_time}" =~ ^[0-9]+$ ]]; then
        change_epoch="${change_time}"
    else
        change_epoch="$(date -d "${change_time}" +%s 2>/dev/null || echo 0)"
    fi

    local window_start=$(( change_epoch - CORRELATE_WINDOW ))

    declare -A ip_scores
    declare -A ip_sources
    declare -A ip_details

    check_web_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources
    check_ftp_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources
    check_ssh_logs "${window_start}" "${change_epoch}" ip_scores ip_sources
    check_cpanel_logs "${filepath}" "${window_start}" "${change_epoch}" ip_scores ip_sources

    print_header "IP Correlation Report"
    print_row "File" "${filepath}"
    print_row "Change time" "$(epoch_to_date "${change_epoch}")"
    print_row "Search window" "${CORRELATE_WINDOW}s before change"
    echo ""

    if [[ ${#ip_scores[@]} -eq 0 ]]; then
        print_status "info" "No IPs correlated with this file change"
        return 1
    fi

    printf "  ${BOLD}%-18s %-10s %-15s %s${NC}\n" "IP" "SCORE" "CONFIDENCE" "SOURCES"
    print_separator 70

    # Sort by score (descending)
    for ip in $(for k in "${!ip_scores[@]}"; do echo "${ip_scores[$k]} $k"; done | sort -rn | awk '{print $2}'); do
        local score="${ip_scores[${ip}]}"
        local sources="${ip_sources[${ip}]:-unknown}"
        local confidence="LOW"
        local color="${BLUE}"

        if [[ "${score}" -ge "${CONFIDENCE_HIGH}" ]]; then
            confidence="HIGH"
            color="${RED}"
        elif [[ "${score}" -ge "${CONFIDENCE_MEDIUM}" ]]; then
            confidence="MEDIUM"
            color="${YELLOW}"
        fi

        printf "  %-18s ${color}%-10s %-15s${NC} %s\n" "${ip}" "${score}%" "${confidence}" "${sources}"
    done
}

# =============================================================================
# LOG SOURCE: Apache/Nginx Access Logs
# =============================================================================

check_web_logs() {
    local filepath="$1"
    local window_start="$2"
    local window_end="$3"
    local -n scores_ref=$4
    local -n sources_ref=$5

    # Find access logs
    local -a log_files=()
    for log_path in \
        /var/log/apache2/access.log \
        /var/log/apache2/access_log \
        /var/log/httpd/access_log \
        /usr/local/apache/logs/access_log \
        /var/log/nginx/access.log \
        /usr/local/lsws/logs/access.log; do
        [[ -f "${log_path}" ]] && log_files+=("${log_path}")
    done

    # Also check domain-specific logs
    for domain_log in /var/log/apache2/domlogs/* /usr/local/apache/domlogs/*; do
        [[ -f "${domain_log}" ]] && log_files+=("${domain_log}")
    done

    [[ ${#log_files[@]} -eq 0 ]] && return

    # Build search patterns based on file path
    local filename
    filename="$(basename "${filepath}")"
    local rel_path="${filepath#/var/www/}"
    rel_path="${rel_path#/home/*/public_html/}"

    for log_file in "${log_files[@]}"; do
        # Look for POST requests to WordPress admin, file upload endpoints, or the file itself
        local -a patterns=(
            "POST.*wp-admin"
            "POST.*wp-login"
            "POST.*xmlrpc.php"
            "POST.*${filename}"
            "POST.*plugin-editor"
            "POST.*theme-editor"
            "POST.*upload"
        )

        for pattern in "${patterns[@]}"; do
            while IFS= read -r line; do
                local ip
                ip="$(echo "${line}" | awk '{print $1}')"

                # Validate IP
                validate_ip "${ip}" || continue

                # Parse timestamp from Apache log format
                local log_time
                log_time="$(echo "${line}" | grep -oP '\[[\d/\w:+ ]+\]' | tr -d '[]')"
                local log_epoch
                log_epoch="$(date -d "${log_time}" +%s 2>/dev/null || echo 0)"

                # Check if within time window
                if [[ "${log_epoch}" -ge "${window_start}" ]] && [[ "${log_epoch}" -le "${window_end}" ]]; then
                    local time_diff=$(( window_end - log_epoch ))
                    local score=40

                    # Closer in time = higher score
                    if [[ "${time_diff}" -lt 30 ]]; then
                        score=90
                    elif [[ "${time_diff}" -lt 60 ]]; then
                        score=70
                    elif [[ "${time_diff}" -lt 120 ]]; then
                        score=50
                    fi

                    # POST to the exact file = bonus
                    if echo "${line}" | grep -q "${filename}"; then
                        score=$(( score + 15 ))
                    fi

                    # Cap at 100
                    [[ "${score}" -gt 100 ]] && score=100

                    # Keep highest score per IP
                    local existing="${scores_ref[${ip}]:-0}"
                    if [[ "${score}" -gt "${existing}" ]]; then
                        scores_ref["${ip}"]="${score}"
                    fi
                    sources_ref["${ip}"]="${sources_ref[${ip}]:-}web "
                fi
            done < <(grep -E "${pattern}" "${log_file}" 2>/dev/null | tail -100)
        done
    done
}

# =============================================================================
# LOG SOURCE: FTP Transfer Logs
# =============================================================================

check_ftp_logs() {
    local filepath="$1"
    local window_start="$2"
    local window_end="$3"
    local -n scores_ref=$4
    local -n sources_ref=$5

    local -a log_files=()
    for log_path in \
        /var/log/xferlog \
        /var/log/proftpd/xferlog \
        /var/log/vsftpd.log \
        /var/log/pure-ftpd/transfer.log; do
        [[ -f "${log_path}" ]] && log_files+=("${log_path}")
    done

    [[ ${#log_files[@]} -eq 0 ]] && return

    local filename
    filename="$(basename "${filepath}")"

    for log_file in "${log_files[@]}"; do
        while IFS= read -r line; do
            # xferlog format: timestamp duration host size filename type direction ...
            local ip
            ip="$(echo "${line}" | awk '{print $7}')"
            validate_ip "${ip}" || continue

            local log_time
            log_time="$(echo "${line}" | awk '{print $1" "$2" "$3" "$4" "$5}')"
            local log_epoch
            log_epoch="$(date -d "${log_time}" +%s 2>/dev/null || echo 0)"

            if [[ "${log_epoch}" -ge "${window_start}" ]] && [[ "${log_epoch}" -le "${window_end}" ]]; then
                local score=60  # FTP upload is strong evidence

                if echo "${line}" | grep -qi "STOR\|i "; then  # Upload indicator
                    score=75
                fi

                local existing="${scores_ref[${ip}]:-0}"
                if [[ "${score}" -gt "${existing}" ]]; then
                    scores_ref["${ip}"]="${score}"
                fi
                sources_ref["${ip}"]="${sources_ref[${ip}]:-}ftp "
            fi
        done < <(grep -i "${filename}" "${log_file}" 2>/dev/null | tail -50)
    done
}

# =============================================================================
# LOG SOURCE: SSH Auth Logs
# =============================================================================

check_ssh_logs() {
    local window_start="$1"
    local window_end="$2"
    local -n scores_ref=$3
    local -n sources_ref=$4

    local log_file="/var/log/auth.log"
    [[ ! -f "${log_file}" ]] && log_file="/var/log/secure"
    [[ ! -f "${log_file}" ]] && return

    while IFS= read -r line; do
        local ip
        ip="$(echo "${line}" | grep -oP 'from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')"
        [[ -z "${ip}" ]] && continue
        validate_ip "${ip}" || continue

        local log_time
        log_time="$(echo "${line}" | awk '{print $1" "$2" "$3}')"
        local log_epoch
        log_epoch="$(date -d "${log_time}" +%s 2>/dev/null || echo 0)"

        if [[ "${log_epoch}" -ge "${window_start}" ]] && [[ "${log_epoch}" -le "${window_end}" ]]; then
            local score=30  # SSH is indirect evidence

            if echo "${line}" | grep -q "Accepted"; then
                score=45  # Successful login is stronger
            fi

            local existing="${scores_ref[${ip}]:-0}"
            if [[ "${score}" -gt "${existing}" ]]; then
                scores_ref["${ip}"]="${score}"
            fi
            sources_ref["${ip}"]="${sources_ref[${ip}]:-}ssh "
        fi
    done < <(grep "sshd.*session opened\|sshd.*Accepted" "${log_file}" 2>/dev/null | tail -50)
}

# =============================================================================
# LOG SOURCE: cPanel File Manager
# =============================================================================

check_cpanel_logs() {
    local filepath="$1"
    local window_start="$2"
    local window_end="$3"
    local -n scores_ref=$4
    local -n sources_ref=$5

    local log_dir="/usr/local/cpanel/logs"
    [[ ! -d "${log_dir}" ]] && return

    local filename
    filename="$(basename "${filepath}")"

    # cPanel access log
    local access_log="${log_dir}/access_log"
    [[ ! -f "${access_log}" ]] && return

    while IFS= read -r line; do
        local ip
        ip="$(echo "${line}" | awk '{print $1}')"
        validate_ip "${ip}" || continue

        if echo "${line}" | grep -qi "filemanager\|editit\|savefile"; then
            local log_time
            log_time="$(echo "${line}" | grep -oP '\[[\d/\w:+ ]+\]' | tr -d '[]')"
            local log_epoch
            log_epoch="$(date -d "${log_time}" +%s 2>/dev/null || echo 0)"

            if [[ "${log_epoch}" -ge "${window_start}" ]] && [[ "${log_epoch}" -le "${window_end}" ]]; then
                local score=65  # cPanel file edit is strong evidence

                if echo "${line}" | grep -q "${filename}"; then
                    score=85  # Editing the exact file
                fi

                local existing="${scores_ref[${ip}]:-0}"
                if [[ "${score}" -gt "${existing}" ]]; then
                    scores_ref["${ip}"]="${score}"
                fi
                sources_ref["${ip}"]="${sources_ref[${ip}]:-}cpanel "
            fi
        fi
    done < <(grep "${filename}" "${access_log}" 2>/dev/null | tail -50)
}
