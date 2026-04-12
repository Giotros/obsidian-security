#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Central API Server (CGI)
# Handles ban synchronization across all connected agents
# Runs as Apache CGI script — no dependencies needed
#
# Actions: pull, push, remove, status, history, heartbeat
# Auth: Bearer token (256-bit)
# =============================================================================

set -euo pipefail

# CGI environment
export OBSIDIAN_DIR="${OBSIDIAN_DIR:-/opt/obsidian}"
export OBSIDIAN_DATA="${OBSIDIAN_DATA:-${OBSIDIAN_DIR}/data}"
export OBSIDIAN_LOGS="${OBSIDIAN_LOGS:-${OBSIDIAN_DIR}/logs}"

# Source minimal libraries (avoid sourcing everything for CGI performance)
source "${OBSIDIAN_DIR}/lib/common.sh" 2>/dev/null || true

# Files
readonly API_TOKEN_FILE="${OBSIDIAN_DATA}/api_token"
readonly API_BANS_FILE="${OBSIDIAN_DATA}/bans.txt"
readonly API_HISTORY_FILE="${OBSIDIAN_DATA}/ban_history.log"
readonly API_HEARTBEATS_FILE="${OBSIDIAN_DATA}/heartbeats.txt"
readonly API_RATE_DIR="${OBSIDIAN_DATA}/rate_limits"

# Rate limiting
readonly MAX_REQUESTS_PER_MINUTE=100

# =============================================================================
# CGI HELPERS
# =============================================================================

send_response() {
    local status_code="$1"
    local body="$2"

    echo "Status: ${status_code}"
    echo "Content-Type: application/json"
    echo "X-Obsidian-Version: ${OBSIDIAN_VERSION:-1.0.0}"
    echo ""
    echo "${body}"
    exit 0
}

send_error() {
    local code="$1"
    local message="$2"
    send_response "${code}" "$(json_response "error" "${message}")"
}

send_success() {
    local message="$1"
    local data="${2:-}"
    send_response "200" "$(json_response "success" "${message}" "${data}")"
}

# Read POST body
read_post_body() {
    local length="${CONTENT_LENGTH:-0}"
    if [[ "${length}" -gt 0 ]] && [[ "${length}" -lt 1048576 ]]; then
        head -c "${length}"
    fi
}

# Parse query string
get_param() {
    local key="$1"
    echo "${QUERY_STRING:-}" | tr '&' '\n' | grep "^${key}=" | cut -d= -f2- | head -1
}

# Get client IP
get_client_ip() {
    echo "${REMOTE_ADDR:-${HTTP_X_FORWARDED_FOR:-unknown}}"
}

# =============================================================================
# AUTHENTICATION
# =============================================================================

authenticate() {
    local auth_header="${HTTP_AUTHORIZATION:-}"

    if [[ -z "${auth_header}" ]]; then
        send_error "401" "Missing Authorization header"
    fi

    # Extract token from "Bearer <token>"
    local token="${auth_header#Bearer }"
    token="${token# }"

    if [[ -z "${token}" ]]; then
        send_error "401" "Invalid Authorization format"
    fi

    # Compare with stored token
    local stored_token=""
    if [[ -f "${API_TOKEN_FILE}" ]]; then
        stored_token="$(cat "${API_TOKEN_FILE}" 2>/dev/null | tr -d '[:space:]')"
    fi

    if [[ -z "${stored_token}" ]]; then
        send_error "500" "Server token not configured"
    fi

    if [[ "${token}" != "${stored_token}" ]]; then
        log_warn "Auth failed from $(get_client_ip)"
        send_error "403" "Invalid token"
    fi
}

# =============================================================================
# RATE LIMITING
# =============================================================================

check_rate_limit() {
    local client_ip
    client_ip="$(get_client_ip)"
    local safe_ip
    safe_ip="$(echo "${client_ip}" | tr '.' '_')"

    mkdir -p "${API_RATE_DIR}" 2>/dev/null || true

    local rate_file="${API_RATE_DIR}/${safe_ip}"
    local now
    now="$(date +%s)"
    local window_start=$(( now - 60 ))

    # Clean old entries and count current
    local count=0
    if [[ -f "${rate_file}" ]]; then
        local temp="${rate_file}.tmp"
        while IFS= read -r timestamp; do
            if [[ "${timestamp}" -ge "${window_start}" ]]; then
                echo "${timestamp}" >> "${temp}"
                count=$(( count + 1 ))
            fi
        done < "${rate_file}"
        [[ -f "${temp}" ]] && mv "${temp}" "${rate_file}" || > "${rate_file}"
    fi

    if [[ "${count}" -ge "${MAX_REQUESTS_PER_MINUTE}" ]]; then
        send_error "429" "Rate limit exceeded (${MAX_REQUESTS_PER_MINUTE}/min)"
    fi

    echo "${now}" >> "${rate_file}"
}

# =============================================================================
# API ACTIONS
# =============================================================================

action_pull() {
    # Return current ban list
    if [[ -f "${API_BANS_FILE}" ]]; then
        local data="["
        local first=true
        while IFS='|' read -r ip reason added_by timestamp source; do
            [[ -z "${ip}" ]] && continue
            [[ "${first}" == true ]] && first=false || data="${data},"
            data="${data}{\"ip\":\"${ip}\",\"reason\":\"$(json_escape "${reason}")\",\"added_by\":\"$(json_escape "${added_by}")\",\"timestamp\":${timestamp:-0},\"source\":\"$(json_escape "${source}")\"}"
        done < "${API_BANS_FILE}"
        data="${data}]"
        send_success "Ban list retrieved" "${data}"
    else
        send_success "No bans" "[]"
    fi
}

action_push() {
    local body
    body="$(read_post_body)"

    # Simple JSON field extraction (no jq dependency)
    local ip reason source_info
    ip="$(echo "${body}" | grep -oP '"ip"\s*:\s*"\K[^"]+' | head -1)"
    reason="$(echo "${body}" | grep -oP '"reason"\s*:\s*"\K[^"]+' | head -1)"
    source_info="$(echo "${body}" | grep -oP '"source"\s*:\s*"\K[^"]+' | head -1)"

    # Validate IP
    if [[ -z "${ip}" ]]; then
        send_error "400" "Missing IP address"
    fi

    # Validate IP using validate_ip function
    if ! validate_ip "${ip}"; then
        send_error "400" "Invalid IP format"
    fi

    # Check if already banned
    if [[ -f "${API_BANS_FILE}" ]] && grep -Fq "^${ip}|" "${API_BANS_FILE}" 2>/dev/null; then
        send_success "Already banned" "{\"ip\":\"${ip}\"}"
    fi

    # Sanitize
    local safe_reason
    safe_reason="$(echo "${reason:-No reason}" | tr -cd 'a-zA-Z0-9 ._:@/-' | head -c 256)"

    local timestamp
    timestamp="$(date +%s)"
    local agent_name
    agent_name="$(sanitize_input "${HTTP_X_AGENT_NAME:-unknown}")"

    # Record ban
    echo "${ip}|${safe_reason}|${agent_name}|${timestamp}|${source_info:-push}" >> "${API_BANS_FILE}"

    # Record history
    echo "$(date '+%Y-%m-%d %H:%M:%S')|BAN|${ip}|${safe_reason}|${agent_name}|push" >> "${API_HISTORY_FILE}" 2>/dev/null

    log_info "Ban pushed by ${agent_name}: ${ip} (${safe_reason})"
    send_success "IP banned" "{\"ip\":\"${ip}\",\"reason\":\"$(json_escape "${safe_reason}")\"}"
}

action_remove() {
    local body
    body="$(read_post_body)"
    local ip
    ip="$(echo "${body}" | grep -oP '"ip"\s*:\s*"\K[^"]+' | head -1)"

    if [[ -z "${ip}" ]]; then
        send_error "400" "Missing IP address"
    fi

    if [[ -f "${API_BANS_FILE}" ]]; then
        local before
        before="$(wc -l < "${API_BANS_FILE}")"
        grep -Fv "^${ip}|" "${API_BANS_FILE}" > "${API_BANS_FILE}.tmp" 2>/dev/null || true
        mv "${API_BANS_FILE}.tmp" "${API_BANS_FILE}"
        local after
        after="$(wc -l < "${API_BANS_FILE}")"

        if [[ "${before}" -gt "${after}" ]]; then
            local agent_name
            agent_name="$(sanitize_input "${HTTP_X_AGENT_NAME:-unknown}")"
            echo "$(date '+%Y-%m-%d %H:%M:%S')|UNBAN|${ip}||${agent_name}|api" >> "${API_HISTORY_FILE}" 2>/dev/null
            send_success "IP unbanned" "{\"ip\":\"${ip}\"}"
        else
            send_error "404" "IP not found in ban list"
        fi
    else
        send_error "404" "No ban list exists"
    fi
}

action_status() {
    local ban_count=0
    [[ -f "${API_BANS_FILE}" ]] && ban_count="$(wc -l < "${API_BANS_FILE}" 2>/dev/null || echo 0)"

    local agent_count=0
    if [[ -f "${API_HEARTBEATS_FILE}" ]]; then
        local now
        now="$(date +%s)"
        local cutoff=$(( now - 300 ))  # Active in last 5 minutes
        while IFS='|' read -r name timestamp _; do
            [[ "${timestamp}" -ge "${cutoff}" ]] && agent_count=$(( agent_count + 1 ))
        done < "${API_HEARTBEATS_FILE}"
    fi

    local data="{\"bans\":${ban_count},\"active_agents\":${agent_count},\"version\":\"${OBSIDIAN_VERSION}\",\"uptime\":\"$(uptime -p 2>/dev/null || echo unknown)\"}"
    send_success "Server status" "${data}"
}

action_history() {
    local count
    count="$(get_param "count")"
    count="${count:-30}"

    if [[ ! -f "${API_HISTORY_FILE}" ]]; then
        send_success "No history" "[]"
        return
    fi

    local data="["
    local first=true
    while IFS='|' read -r timestamp action ip reason by source; do
        [[ "${first}" == true ]] && first=false || data="${data},"
        data="${data}{\"timestamp\":\"$(json_escape "${timestamp}")\",\"action\":\"$(json_escape "${action}")\",\"ip\":\"${ip}\",\"reason\":\"$(json_escape "${reason}")\"}"
    done < <(tail -"${count}" "${API_HISTORY_FILE}")
    data="${data}]"

    send_success "History retrieved" "${data}"
}

action_heartbeat() {
    local body
    body="$(read_post_body)"
    local agent_name
    agent_name="$(echo "${body}" | grep -oP '"agent"\s*:\s*"\K[^"]+' | head -1)"
    agent_name="${agent_name:-${HTTP_X_AGENT_NAME:-unknown}}"

    local timestamp
    timestamp="$(date +%s)"
    local client_ip
    client_ip="$(get_client_ip)"

    # Update heartbeat record (replace existing or add new)
    local temp="${API_HEARTBEATS_FILE}.tmp"
    if [[ -f "${API_HEARTBEATS_FILE}" ]]; then
        grep -Fv "^${agent_name}|" "${API_HEARTBEATS_FILE}" > "${temp}" 2>/dev/null || true
    else
        > "${temp}"
    fi
    echo "${agent_name}|${timestamp}|${client_ip}" >> "${temp}"
    mv "${temp}" "${API_HEARTBEATS_FILE}"

    send_success "Heartbeat received" "{\"agent\":\"$(json_escape "${agent_name}")\"}"
}

# =============================================================================
# MAIN REQUEST HANDLER
# =============================================================================

main() {
    # Ensure data directories exist
    mkdir -p "${OBSIDIAN_DATA}" "${OBSIDIAN_LOGS}" "${API_RATE_DIR}" 2>/dev/null || true

    # Rate limit check
    check_rate_limit

    # Authenticate
    authenticate

    # Route action
    local action
    action="$(get_param "action")"

    case "${action}" in
        pull)      action_pull ;;
        push)      action_push ;;
        remove)    action_remove ;;
        status)    action_status ;;
        history)   action_history ;;
        heartbeat) action_heartbeat ;;
        *)         send_error "400" "Unknown action: ${action}" ;;
    esac
}

# Run
main
