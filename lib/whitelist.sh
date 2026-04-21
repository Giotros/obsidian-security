#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — IP Whitelist with CIDR Support
# Manages trusted IPs that should never be banned or alerted on
# =============================================================================

readonly WHITELIST_FILE="${OBSIDIAN_DATA}/whitelist.txt"

# Format: IP_OR_CIDR|REASON|ADDED_BY|TIMESTAMP|EXPIRES
# Expires: 0 = permanent, epoch = auto-expire

# =============================================================================
# WHITELIST MANAGEMENT
# =============================================================================

whitelist_add() {
    local ip="$1"
    local reason="${2:-Manual addition}"
    local added_by="${3:-admin}"
    local expires="${4:-0}"  # 0 = permanent

    # Validate
    if ! validate_ip "${ip}" && ! validate_cidr "${ip}"; then
        log_error "Invalid IP or CIDR: ${ip}"
        return 1
    fi

    # Check if already whitelisted
    if is_whitelisted "${ip}"; then
        log_warn "Already whitelisted: ${ip}"
        return 0
    fi

    local timestamp
    timestamp="$(epoch_now)"
    local safe_reason
    safe_reason="$(sanitize_reason "${reason}")"

    echo "${ip}|${safe_reason}|${added_by}|${timestamp}|${expires}" >> "${WHITELIST_FILE}"
    log_info "Whitelisted: ${ip} (reason: ${safe_reason})"
    return 0
}

whitelist_remove() {
    local ip="$1"

    if [[ ! -f "${WHITELIST_FILE}" ]]; then
        log_warn "Whitelist file not found"
        return 1
    fi

    local count_before
    count_before="$(wc -l < "${WHITELIST_FILE}" 2>/dev/null || echo 0)"

    grep -v "^$(printf '%s' "${ip}" | sed 's/[.[\*^$()+?{|]/\\&/g')|" "${WHITELIST_FILE}" > "${WHITELIST_FILE}.tmp" 2>/dev/null || true
    mv "${WHITELIST_FILE}.tmp" "${WHITELIST_FILE}"

    local count_after
    count_after="$(wc -l < "${WHITELIST_FILE}" 2>/dev/null || echo 0)"

    if [[ "${count_before}" -gt "${count_after}" ]]; then
        log_info "Removed from whitelist: ${ip}"
        return 0
    else
        log_warn "Not found in whitelist: ${ip}"
        return 1
    fi
}

is_whitelisted() {
    local check_ip="$1"

    [[ ! -f "${WHITELIST_FILE}" ]] && return 1

    local now
    now="$(epoch_now)"

    while IFS='|' read -r entry reason added_by timestamp expires; do
        # Skip comments and empty lines
        [[ -z "${entry}" ]] && continue
        [[ "${entry}" =~ ^# ]] && continue

        # Check expiration
        if [[ "${expires}" -gt 0 ]] && [[ "${now}" -gt "${expires}" ]]; then
            continue  # Expired entry
        fi

        # Exact match
        if [[ "${entry}" == "${check_ip}" ]]; then
            return 0
        fi

        # CIDR match — check if the IP falls within a whitelisted range
        if [[ "${entry}" == *"/"* ]]; then
            if validate_cidr "${entry}" && validate_ip "${check_ip}"; then
                if ip_in_cidr "${check_ip}" "${entry}"; then
                    return 0
                fi
            fi
        fi
    done < "${WHITELIST_FILE}"

    return 1
}

whitelist_list() {
    if [[ ! -f "${WHITELIST_FILE}" ]] || [[ ! -s "${WHITELIST_FILE}" ]]; then
        echo "Whitelist is empty."
        return
    fi

    local now
    now="$(epoch_now)"

    print_header "Whitelisted IPs"
    printf "  ${BOLD}%-20s %-30s %-12s %-20s %s${NC}\n" \
        "IP/CIDR" "REASON" "ADDED BY" "DATE" "EXPIRES"
    print_separator 100

    while IFS='|' read -r entry reason added_by timestamp expires; do
        [[ -z "${entry}" ]] && continue
        [[ "${entry}" =~ ^# ]] && continue

        local date_str
        date_str="$(epoch_to_date "${timestamp}")"

        local expire_str="permanent"
        if [[ "${expires}" -gt 0 ]]; then
            if [[ "${now}" -gt "${expires}" ]]; then
                expire_str="${RED}expired${NC}"
            else
                expire_str="$(epoch_to_date "${expires}")"
            fi
        fi

        printf "  %-20s %-30s %-12s %-20s %b\n" \
            "${entry}" "${reason:0:28}" "${added_by:0:10}" "${date_str}" "${expire_str}"
    done < "${WHITELIST_FILE}"
}

# Clean up expired entries
whitelist_cleanup() {
    [[ ! -f "${WHITELIST_FILE}" ]] && return 0

    local now
    now="$(epoch_now)"
    local removed=0

    local temp_file="${WHITELIST_FILE}.tmp"
    > "${temp_file}"

    while IFS='|' read -r entry reason added_by timestamp expires; do
        [[ -z "${entry}" ]] && continue
        if [[ "${expires}" -gt 0 ]] && [[ "${now}" -gt "${expires}" ]]; then
            removed=$(( removed + 1 ))
            log_info "Expired whitelist entry removed: ${entry}"
            continue
        fi
        echo "${entry}|${reason}|${added_by}|${timestamp}|${expires}" >> "${temp_file}"
    done < "${WHITELIST_FILE}"

    mv "${temp_file}" "${WHITELIST_FILE}"
    log_info "Whitelist cleanup: removed ${removed} expired entries"
}

# Add default safe IPs
whitelist_add_defaults() {
    whitelist_add "127.0.0.1" "Localhost" "system" "0" 2>/dev/null || true
    whitelist_add "::1" "Localhost IPv6" "system" "0" 2>/dev/null || true

    # Detect server's own IPs
    local server_ips
    server_ips="$(hostname -I 2>/dev/null || true)"
    for ip in ${server_ips}; do
        if validate_ip "${ip}"; then
            whitelist_add "${ip}" "Server own IP" "system" "0" 2>/dev/null || true
        fi
    done
}
