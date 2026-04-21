#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Firewall Module
# Multi-layer IP banning: CSF → iptables → WHM API
# Evolved from ShieldSync's core banning engine
# =============================================================================

readonly BANS_FILE="${OBSIDIAN_DATA}/bans.txt"
readonly BAN_HISTORY_FILE="${OBSIDIAN_DATA}/ban_history.log"

# Format: IP|REASON|ADDED_BY|TIMESTAMP|SOURCE_MODULE
# SOURCE_MODULE: manual, malware, botguard, correlate, sync, emergency

# =============================================================================
# BAN MANAGEMENT
# =============================================================================

ban_ip() {
    local ip="$1"
    local reason="${2:-No reason specified}"
    local added_by="${3:-admin}"
    local source_module="${4:-manual}"

    # Validate IP
    if ! validate_ip "${ip}" && ! validate_cidr "${ip}"; then
        log_error "Invalid IP or CIDR: ${ip}"
        return 1
    fi

    # Never ban whitelisted IPs
    if is_whitelisted "${ip}"; then
        log_warn "Cannot ban whitelisted IP: ${ip}"
        return 1
    fi

    # Never ban private IPs (safety net)
    if validate_ip "${ip}" && is_private_ip "${ip}"; then
        local allow_private
        allow_private="$(get_config 'allow_ban_private' 'false')"
        if [[ "${allow_private}" != "true" ]]; then
            log_warn "Refusing to ban private IP: ${ip} (set allow_ban_private=true to override)"
            return 1
        fi
    fi

    # Check if already banned
    if is_banned "${ip}"; then
        log_warn "Already banned: ${ip}"
        return 0
    fi

    local safe_reason
    safe_reason="$(sanitize_reason "${reason}")"
    local timestamp
    timestamp="$(epoch_now)"

    # Apply ban at firewall level
    if ! apply_firewall_ban "${ip}" "${safe_reason}"; then
        log_error "Failed to apply firewall ban for: ${ip}"
        return 1
    fi

    # Apply ban at application level (WHM)
    apply_whm_ban "${ip}" 2>/dev/null || true

    # Record the ban
    acquire_lock "${OBSIDIAN_DATA}/bans.lock" 10 || return 1
    echo "${ip}|${safe_reason}|${added_by}|${timestamp}|${source_module}" >> "${BANS_FILE}"
    release_lock "${OBSIDIAN_DATA}/bans.lock"

    # Record in history
    echo "$(date '+%Y-%m-%d %H:%M:%S')|BAN|${ip}|${safe_reason}|${added_by}|${source_module}" >> "${BAN_HISTORY_FILE}" 2>/dev/null || true

    log_info "Banned: ${ip} (reason: ${safe_reason}, source: ${source_module})"

    # Alert on ban (for non-sync bans)
    if [[ "${source_module}" != "sync" ]]; then
        send_alert "${SEVERITY_HIGH}" "Firewall" "IP Banned" \
            "IP ${ip} has been banned.\nReason: ${safe_reason}\nSource: ${source_module}\nBanned by: ${added_by}" &
    fi

    return 0
}

unban_ip() {
    local ip="$1"
    local removed_by="${2:-admin}"

    if ! is_banned "${ip}"; then
        log_warn "Not currently banned: ${ip}"
        return 1
    fi

    # Remove from firewall
    remove_firewall_ban "${ip}" 2>/dev/null || true

    # Remove from WHM
    remove_whm_ban "${ip}" 2>/dev/null || true

    # Remove from bans file
    acquire_lock "${OBSIDIAN_DATA}/bans.lock" 10 || return 1
    if [[ -f "${BANS_FILE}" ]]; then
        grep -v "^$(printf '%s' "${ip}" | sed 's/[.[\*^$()+?{|]/\\&/g')|" "${BANS_FILE}" > "${BANS_FILE}.tmp" 2>/dev/null || true
        mv "${BANS_FILE}.tmp" "${BANS_FILE}"
    fi
    release_lock "${OBSIDIAN_DATA}/bans.lock"

    # Record in history
    echo "$(date '+%Y-%m-%d %H:%M:%S')|UNBAN|${ip}||${removed_by}|manual" >> "${BAN_HISTORY_FILE}" 2>/dev/null || true

    log_info "Unbanned: ${ip} (by: ${removed_by})"
    return 0
}

is_banned() {
    local ip="$1"
    [[ -f "${BANS_FILE}" ]] && grep -q "^$(printf '%s' "${ip}" | sed 's/[.[\*^$()+?{|]/\\&/g')|" "${BANS_FILE}" 2>/dev/null
}

get_ban_info() {
    local ip="$1"
    [[ -f "${BANS_FILE}" ]] && grep "^${ip}|" "${BANS_FILE}" 2>/dev/null | head -1
}

list_bans() {
    if [[ ! -f "${BANS_FILE}" ]] || [[ ! -s "${BANS_FILE}" ]]; then
        echo "No active bans."
        return
    fi

    print_header "Active IP Bans"
    printf "  ${BOLD}%-18s %-25s %-10s %-20s %s${NC}\n" \
        "IP" "REASON" "BY" "DATE" "SOURCE"
    print_separator 95

    while IFS='|' read -r ip reason added_by timestamp source; do
        [[ -z "${ip}" ]] && continue
        local date_str
        date_str="$(epoch_to_date "${timestamp}")"
        printf "  %-18s %-25s %-10s %-20s %s\n" \
            "${ip}" "${reason:0:23}" "${added_by:0:8}" "${date_str}" "${source}"
    done < "${BANS_FILE}"

    echo ""
    local total
    total="$(wc -l < "${BANS_FILE}" 2>/dev/null || echo 0)"
    echo -e "  Total active bans: ${BOLD}${total}${NC}"
}

ban_count() {
    if [[ -f "${BANS_FILE}" ]]; then
        wc -l < "${BANS_FILE}" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# =============================================================================
# FIREWALL LAYER (CSF / iptables / nftables)
# =============================================================================

apply_firewall_ban() {
    local ip="$1"
    local reason="${2:-Obsidian ban}"
    local firewall
    firewall="$(detect_firewall)"

    case "${firewall}" in
        csf)
            csf -d "${ip}" "Obsidian: ${reason}" 2>/dev/null
            ;;
        iptables)
            # Check if rule already exists
            if ! iptables -C INPUT -s "${ip}" -j DROP 2>/dev/null; then
                iptables -I INPUT -s "${ip}" -j DROP 2>/dev/null
            fi
            ;;
        nftables)
            nft add rule inet filter input ip saddr "${ip}" drop 2>/dev/null
            ;;
        none)
            log_warn "No firewall detected — ban recorded but not enforced at network level"
            return 0
            ;;
    esac

    log_debug "Firewall ban applied (${firewall}): ${ip}"
    return 0
}

remove_firewall_ban() {
    local ip="$1"
    local firewall
    firewall="$(detect_firewall)"

    case "${firewall}" in
        csf)
            csf -dr "${ip}" 2>/dev/null || true
            ;;
        iptables)
            iptables -D INPUT -s "${ip}" -j DROP 2>/dev/null || true
            ;;
        nftables)
            # nftables removal requires handle — simplified approach
            nft -a list ruleset 2>/dev/null | grep "${ip}" | while read -r line; do
                local handle
                handle="$(echo "${line}" | grep -oP 'handle \K[0-9]+')"
                [[ -n "${handle}" ]] && nft delete rule inet filter input handle "${handle}" 2>/dev/null || true
            done
            ;;
    esac

    log_debug "Firewall ban removed: ${ip}"
}

# =============================================================================
# WHM/cPanel APPLICATION LAYER
# =============================================================================

apply_whm_ban() {
    local ip="$1"

    if ! is_cpanel; then
        return 0
    fi

    if command -v whmapi1 &>/dev/null; then
        whmapi1 addip ip="${ip}" 2>/dev/null || true
        log_debug "WHM application ban applied: ${ip}"
    fi
}

remove_whm_ban() {
    local ip="$1"

    if ! is_cpanel && ! command -v whmapi1 &>/dev/null; then
        return 0
    fi

    whmapi1 removeip ip="${ip}" 2>/dev/null || true
    log_debug "WHM application ban removed: ${ip}"
}

# =============================================================================
# IMPORT / EXPORT
# =============================================================================

import_bans() {
    local file="$1"
    local imported=0
    local skipped=0

    if [[ ! -f "${file}" ]]; then
        log_error "Import file not found: ${file}"
        return 1
    fi

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^# ]] && continue

        local ip
        ip="$(echo "${line}" | cut -d'|' -f1 | xargs)"

        if validate_ip "${ip}" || validate_cidr "${ip}"; then
            if ban_ip "${ip}" "Imported" "import" "import" 2>/dev/null; then
                imported=$(( imported + 1 ))
            else
                skipped=$(( skipped + 1 ))
            fi
        else
            skipped=$(( skipped + 1 ))
        fi
    done < "${file}"

    log_info "Import complete: ${imported} imported, ${skipped} skipped"
    echo "Imported: ${imported}, Skipped: ${skipped}"
}

export_bans() {
    local output_file="$1"

    if [[ ! -f "${BANS_FILE}" ]]; then
        log_warn "No bans to export"
        return 1
    fi

    cp "${BANS_FILE}" "${output_file}"
    local count
    count="$(wc -l < "${output_file}" 2>/dev/null || echo 0)"
    log_info "Exported ${count} bans to ${output_file}"
    echo "Exported ${count} bans to ${output_file}"
}

# =============================================================================
# EMERGENCY BAN (immediate, all layers, highest priority)
# =============================================================================

emergency_ban() {
    local ip="$1"
    local reason="${2:-Emergency ban}"

    log_critical "EMERGENCY BAN: ${ip} — ${reason}"

    # Bypass all checks except whitelist
    if is_whitelisted "${ip}"; then
        log_error "Cannot emergency ban whitelisted IP: ${ip}"
        return 1
    fi

    # Apply at all layers immediately
    apply_firewall_ban "${ip}" "EMERGENCY: ${reason}"
    apply_whm_ban "${ip}"

    # Record
    local timestamp
    timestamp="$(epoch_now)"
    echo "${ip}|EMERGENCY: ${reason}|admin|${timestamp}|emergency" >> "${BANS_FILE}" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S')|EMERGENCY_BAN|${ip}|${reason}|admin|emergency" >> "${BAN_HISTORY_FILE}" 2>/dev/null

    # Alert immediately (not async)
    send_alert "${SEVERITY_CRITICAL}" "Firewall" "Emergency Ban" \
        "EMERGENCY: IP ${ip} banned across all layers.\nReason: ${reason}"

    echo -e "${RED}${BOLD}EMERGENCY BAN APPLIED: ${ip}${NC}"
}

# =============================================================================
# BAN HISTORY
# =============================================================================

show_ban_history() {
    local count="${1:-30}"

    if [[ ! -f "${BAN_HISTORY_FILE}" ]]; then
        echo "No ban history found."
        return
    fi

    print_header "Ban History (last ${count})"
    printf "  ${BOLD}%-20s %-12s %-18s %-25s %s${NC}\n" \
        "TIMESTAMP" "ACTION" "IP" "REASON" "BY"
    print_separator 95

    tail -"${count}" "${BAN_HISTORY_FILE}" | while IFS='|' read -r timestamp action ip reason by source; do
        local color="${GREEN}"
        [[ "${action}" == *"BAN"* ]] && [[ "${action}" != *"UNBAN"* ]] && color="${RED}"
        printf "  %-20s ${color}%-12s${NC} %-18s %-25s %s\n" \
            "${timestamp}" "${action}" "${ip}" "${reason:0:23}" "${by}"
    done
}
