#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Sync Agent
# Runs on each server, syncs bans with central Obsidian server
# Pull-based: agent polls central API every N seconds
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBSIDIAN_DIR="${OBSIDIAN_DIR:-/opt/obsidian}"

# Source libraries
source "${OBSIDIAN_DIR}/lib/common.sh"
source "${OBSIDIAN_DIR}/lib/firewall.sh"
source "${OBSIDIAN_DIR}/lib/whitelist.sh"
source "${OBSIDIAN_DIR}/lib/alert.sh"

# Agent configuration
AGENT_CONF="${OBSIDIAN_DIR}/agent.conf"
SYNC_INTERVAL="${SYNC_INTERVAL:-60}"
CENTRAL_URL="${CENTRAL_URL:-}"
CENTRAL_TOKEN="${CENTRAL_TOKEN:-}"
AGENT_NAME="${AGENT_NAME:-$(hostname -s)}"

# =============================================================================
# LOAD AGENT CONFIG
# =============================================================================

load_agent_config() {
    if [[ -f "${AGENT_CONF}" ]]; then
        while IFS='=' read -r key value; do
            [[ -z "${key}" ]] && continue
            [[ "${key}" =~ ^# ]] && continue
            key="$(echo "${key}" | xargs)"
            value="$(echo "${value}" | sed 's/^["'\'']*//;s/["'\'']*$//' | xargs)"

            case "${key}" in
                central_url)    CENTRAL_URL="${value}" ;;
                central_token)  CENTRAL_TOKEN="${value}" ;;
                sync_interval)  SYNC_INTERVAL="${value}" ;;
                agent_name)     AGENT_NAME="${value}" ;;
            esac
        done < "${AGENT_CONF}"
    fi

    if [[ -z "${CENTRAL_URL}" ]] || [[ -z "${CENTRAL_TOKEN}" ]]; then
        log_error "Missing central_url or central_token in ${AGENT_CONF}"
        return 1
    fi
}

# =============================================================================
# API COMMUNICATION
# =============================================================================

api_request() {
    local action="$1"
    local data="${2:-}"

    local url="${CENTRAL_URL}?action=${action}"
    local -a curl_args=(
        -s --max-time 30
        -H "Authorization: Bearer ${CENTRAL_TOKEN}"
        -H "X-Agent-Name: ${AGENT_NAME}"
        -H "Content-Type: application/json"
    )

    if [[ -n "${data}" ]]; then
        curl_args+=(-d "${data}")
    fi

    local response
    response="$(curl "${curl_args[@]}" "${url}" 2>/dev/null)" || {
        log_error "API request failed: ${action}"
        return 1
    }

    echo "${response}"
}

# =============================================================================
# SYNC ENGINE
# =============================================================================

sync_bans() {
    log_debug "Starting ban sync..."

    # Pull current ban list from central server
    local response
    response="$(api_request "pull")" || {
        log_error "Failed to pull ban list from central server"
        return 1
    }

    # Parse response — extract IPs (simple line-based format)
    # Expected format: one ban per line, pipe-delimited
    local remote_bans_file="${OBSIDIAN_DATA}/remote_bans.tmp"
    echo "${response}" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' > "${remote_bans_file}" 2>/dev/null || true

    if [[ ! -s "${remote_bans_file}" ]]; then
        log_debug "No bans from central server (or empty response)"
        rm -f "${remote_bans_file}"
        return 0
    fi

    local added=0
    local removed=0

    # Add new bans (exist on central but not locally)
    while IFS= read -r ip; do
        [[ -z "${ip}" ]] && continue
        validate_ip "${ip}" || continue

        if ! is_banned "${ip}"; then
            if ban_ip "${ip}" "Synced from central" "sync-agent" "sync"; then
                added=$(( added + 1 ))
                log_info "Synced ban: ${ip}"
            fi
        fi
    done < "${remote_bans_file}"

    # Remove bans that were lifted centrally (exist locally but not on central)
    if [[ -f "${BANS_FILE}" ]]; then
        while IFS='|' read -r ip reason by timestamp source; do
            [[ -z "${ip}" ]] && continue
            [[ "${source}" != "sync" ]] && continue  # Only manage synced bans

            if ! grep -q "^${ip}$" "${remote_bans_file}" 2>/dev/null; then
                unban_ip "${ip}" "sync-agent" 2>/dev/null
                removed=$(( removed + 1 ))
                log_info "Synced unban: ${ip}"
            fi
        done < "${BANS_FILE}"
    fi

    rm -f "${remote_bans_file}"

    if [[ "${added}" -gt 0 ]] || [[ "${removed}" -gt 0 ]]; then
        log_info "Sync complete: +${added} bans, -${removed} unbans"
    else
        log_debug "Sync complete: no changes"
    fi
}

# =============================================================================
# HEARTBEAT
# =============================================================================

send_heartbeat() {
    local ban_count
    ban_count="$(ban_count 2>/dev/null || echo 0)"

    local payload="{
        \"agent\": \"$(json_escape "${AGENT_NAME}")\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",
        \"bans\": ${ban_count},
        \"uptime\": \"$(uptime -p 2>/dev/null || echo 'unknown')\",
        \"version\": \"${OBSIDIAN_VERSION}\"
    }"

    api_request "heartbeat" "${payload}" >/dev/null 2>&1 || \
        log_warn "Heartbeat failed"
}

# =============================================================================
# PUSH BAN TO CENTRAL (for locally-detected threats)
# =============================================================================

push_ban_to_central() {
    local ip="$1"
    local reason="$2"
    local source_module="${3:-agent}"

    local payload="{
        \"action\": \"push\",
        \"ip\": \"${ip}\",
        \"reason\": \"$(json_escape "${reason}")\",
        \"source\": \"$(json_escape "${AGENT_NAME}:${source_module}")\",
        \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"
    }"

    api_request "push" "${payload}" >/dev/null 2>&1 || {
        log_warn "Failed to push ban to central: ${ip}"
        return 1
    }

    log_info "Pushed ban to central: ${ip} (${reason})"
}

# =============================================================================
# AGENT MAIN LOOP
# =============================================================================

agent_cleanup() {
    remove_pid "agent"
    release_lock "${OBSIDIAN_DATA}/agent.lock" 2>/dev/null || true
    log_info "Obsidian Agent stopped"
}

run_agent() {
    load_agent_config || exit 1
    init_directories

    # Check if already running
    if is_running "agent"; then
        log_error "Agent is already running"
        exit 1
    fi

    # Setup
    write_pid "agent"
    setup_signal_handlers "agent_cleanup"

    log_info "Obsidian Agent started (sync every ${SYNC_INTERVAL}s)"
    log_info "Central server: ${CENTRAL_URL}"
    log_info "Agent name: ${AGENT_NAME}"

    local heartbeat_counter=0
    local heartbeat_interval=10  # Send heartbeat every 10 sync cycles

    while true; do
        # Sync bans
        sync_bans 2>/dev/null || log_warn "Sync cycle failed"

        # Periodic heartbeat
        heartbeat_counter=$(( heartbeat_counter + 1 ))
        if [[ "${heartbeat_counter}" -ge "${heartbeat_interval}" ]]; then
            send_heartbeat
            heartbeat_counter=0
        fi

        sleep "${SYNC_INTERVAL}"
    done
}

# =============================================================================
# ENTRY POINT
# =============================================================================

case "${1:-}" in
    start)
        run_agent
        ;;
    stop)
        if is_running "agent"; then
            local pid
            pid="$(cat "$(get_pid_file "agent")" 2>/dev/null)"
            kill "${pid}" 2>/dev/null
            echo "Agent stopped (PID: ${pid})"
        else
            echo "Agent is not running"
        fi
        ;;
    status)
        if is_running "agent"; then
            echo "Agent is running (PID: $(cat "$(get_pid_file "agent")" 2>/dev/null))"
        else
            echo "Agent is not running"
        fi
        ;;
    *)
        echo "Usage: obsidian-agent.sh {start|stop|status}"
        exit 1
        ;;
esac
