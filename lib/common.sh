#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Shared Library
# Common functions used across all modules
# =============================================================================

# Strict mode
set -euo pipefail

# Version
readonly OBSIDIAN_VERSION="1.0.0"

# Colors (only if terminal supports it)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly MAGENTA='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' BOLD='' NC=''
fi

# Default paths
readonly OBSIDIAN_DIR="${OBSIDIAN_DIR:-/opt/obsidian}"
readonly OBSIDIAN_CONF="${OBSIDIAN_CONF:-${OBSIDIAN_DIR}/obsidian.conf}"
readonly OBSIDIAN_DATA="${OBSIDIAN_DATA:-${OBSIDIAN_DIR}/data}"
readonly OBSIDIAN_LOGS="${OBSIDIAN_LOGS:-${OBSIDIAN_DIR}/logs}"
readonly OBSIDIAN_RUN="${OBSIDIAN_RUN:-/var/run/obsidian}"
readonly OBSIDIAN_LOCK="${OBSIDIAN_LOCK:-${OBSIDIAN_RUN}/obsidian.lock}"

# =============================================================================
# LOGGING
# =============================================================================

# Log levels: DEBUG=0, INFO=1, WARN=2, ERROR=3, CRITICAL=4
declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
LOG_LEVEL="${LOG_LEVEL:-INFO}"

log() {
    local level="${1:-INFO}"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Check if we should log this level
    local current_level="${LOG_LEVELS[${LOG_LEVEL}]:-1}"
    local msg_level="${LOG_LEVELS[${level}]:-1}"
    [[ "${msg_level}" -lt "${current_level}" ]] && return 0

    # Color per level
    local color="${NC}"
    case "${level}" in
        DEBUG)    color="${CYAN}" ;;
        INFO)     color="${GREEN}" ;;
        WARN)     color="${YELLOW}" ;;
        ERROR)    color="${RED}" ;;
        CRITICAL) color="${RED}${BOLD}" ;;
    esac

    # Write to log file if available
    local log_file="${OBSIDIAN_LOGS}/obsidian.log"
    if [[ -d "${OBSIDIAN_LOGS}" ]] && [[ -w "${OBSIDIAN_LOGS}" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "${log_file}" 2>/dev/null || true
    fi

    # Write to stderr for visibility
    echo -e "${color}[${timestamp}] [${level}]${NC} ${message}" >&2
}

log_debug()    { log "DEBUG" "$@"; }
log_info()     { log "INFO" "$@"; }
log_warn()     { log "WARN" "$@"; }
log_error()    { log "ERROR" "$@"; }
log_critical() { log "CRITICAL" "$@"; }

# =============================================================================
# CONFIGURATION
# =============================================================================

# Load config file into associative array
declare -A CONFIG

load_config() {
    local config_file="${1:-${OBSIDIAN_CONF}}"

    if [[ ! -f "${config_file}" ]]; then
        log_warn "Config file not found: ${config_file}, using defaults"
        return 1
    fi

    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ -z "${key}" ]] && continue
        [[ "${key}" =~ ^[[:space:]]*# ]] && continue

        # Trim whitespace
        key="$(echo "${key}" | xargs)"
        value="$(echo "${value}" | sed 's/^["'\'']*//;s/["'\'']*$//' | xargs)"

        CONFIG["${key}"]="${value}"
    done < "${config_file}"

    log_debug "Loaded config from ${config_file} (${#CONFIG[@]} entries)"
    return 0
}

get_config() {
    local key="$1"
    local default="${2:-}"
    echo "${CONFIG[${key}]:-${default}}"
}

# =============================================================================
# IP VALIDATION & MANIPULATION
# =============================================================================

validate_ip() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -ra octets <<< "${ip}"

    [[ ${#octets[@]} -ne 4 ]] && return 1

    for octet in "${octets[@]}"; do
        # Must be numeric
        [[ ! "${octet}" =~ ^[0-9]+$ ]] && return 1
        # Must be 0-255
        [[ "${octet}" -gt 255 ]] && return 1
    done
    return 0
}

validate_cidr() {
    local cidr="$1"

    if [[ ! "${cidr}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        return 1
    fi

    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"

    validate_ip "${ip}" || return 1
    [[ "${prefix}" -gt 32 ]] && return 1

    return 0
}

# Convert IP to 32-bit integer for CIDR math
ip_to_num() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -ra octets <<< "${ip}"
    echo $(( (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3] ))
}

# Check if IP is in CIDR range
ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    local network="${cidr%/*}"
    local prefix="${cidr#*/}"

    local ip_num network_num mask

    ip_num=$(ip_to_num "${ip}")
    network_num=$(ip_to_num "${network}")

    # Build mask: shift left by (32 - prefix) then AND with 0xFFFFFFFF
    if [[ "${prefix}" -eq 0 ]]; then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi

    [[ $(( ip_num & mask )) -eq $(( network_num & mask )) ]]
}

# Check if IP is private/reserved
is_private_ip() {
    local ip="$1"
    ip_in_cidr "${ip}" "10.0.0.0/8" && return 0
    ip_in_cidr "${ip}" "172.16.0.0/12" && return 0
    ip_in_cidr "${ip}" "192.168.0.0/16" && return 0
    ip_in_cidr "${ip}" "127.0.0.0/8" && return 0
    return 1
}

# =============================================================================
# INPUT SANITIZATION
# =============================================================================

sanitize_input() {
    local input="$1"
    # Remove dangerous characters: ;, |, &, `, $, (, ), {, }, <, >, newlines
    echo "${input}" | tr -d ';|&`$(){}/<>\n\r' | head -c 512
}

sanitize_path() {
    local path="$1"
    # Remove path traversal attempts and null bytes
    echo "${path}" | sed 's/\.\.\///g; s/\x00//g' | head -c 1024
}

sanitize_reason() {
    local reason="$1"
    # Allow alphanumeric, spaces, hyphens, periods, colons
    echo "${reason}" | tr -cd 'a-zA-Z0-9 ._:@/-' | head -c 256
}

# =============================================================================
# FILE LOCKING (Mutex)
# =============================================================================

acquire_lock() {
    local lock_file="${1:-${OBSIDIAN_LOCK}}"
    local max_wait="${2:-30}"  # seconds
    local waited=0

    while [[ -d "${lock_file}" ]]; do
        # Check for stale lock (older than 120 seconds)
        if [[ -d "${lock_file}" ]]; then
            local lock_age
            lock_age=$(( $(date +%s) - $(stat -c %Y "${lock_file}" 2>/dev/null || echo 0) ))
            if [[ "${lock_age}" -gt 120 ]]; then
                log_warn "Breaking stale lock (age: ${lock_age}s)"
                rmdir "${lock_file}" 2>/dev/null || true
                break
            fi
        fi

        waited=$(( waited + 1 ))
        if [[ "${waited}" -ge "${max_wait}" ]]; then
            log_error "Could not acquire lock after ${max_wait}s: ${lock_file}"
            return 1
        fi
        sleep 1
    done

    # mkdir is atomic on Linux — either succeeds or fails, no race condition
    if mkdir "${lock_file}" 2>/dev/null; then
        log_debug "Lock acquired: ${lock_file}"
        return 0
    else
        log_error "Failed to acquire lock: ${lock_file}"
        return 1
    fi
}

release_lock() {
    local lock_file="${1:-${OBSIDIAN_LOCK}}"
    if [[ -d "${lock_file}" ]]; then
        rmdir "${lock_file}" 2>/dev/null || true
        log_debug "Lock released: ${lock_file}"
    fi
}

# =============================================================================
# RETRY LOGIC
# =============================================================================

retry_with_backoff() {
    local max_attempts="${1:-3}"
    local base_delay="${2:-2}"
    shift 2
    local cmd=("$@")

    local attempt=1
    while [[ "${attempt}" -le "${max_attempts}" ]]; do
        if "${cmd[@]}"; then
            return 0
        fi

        if [[ "${attempt}" -lt "${max_attempts}" ]]; then
            local delay=$(( base_delay * (2 ** (attempt - 1)) ))
            log_warn "Attempt ${attempt}/${max_attempts} failed, retrying in ${delay}s..."
            sleep "${delay}"
        fi

        attempt=$(( attempt + 1 ))
    done

    log_error "All ${max_attempts} attempts failed for: ${cmd[*]}"
    return 1
}

# =============================================================================
# JSON HELPERS (Pure Bash — no jq dependency)
# =============================================================================

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"   # Backslash
    str="${str//\"/\\\"}"   # Double quote
    str="${str//$'\n'/\\n}" # Newline
    str="${str//$'\r'/\\r}" # Carriage return
    str="${str//$'\t'/\\t}" # Tab
    echo "${str}"
}

json_response() {
    local status="$1"
    local message="$2"
    local data="${3:-}"

    local escaped_msg
    escaped_msg="$(json_escape "${message}")"

    if [[ -n "${data}" ]]; then
        echo "{\"status\":\"${status}\",\"message\":\"${escaped_msg}\",\"data\":${data},\"timestamp\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}"
    else
        echo "{\"status\":\"${status}\",\"message\":\"${escaped_msg}\",\"timestamp\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"}"
    fi
}

# =============================================================================
# TABLE FORMATTING (for CLI output)
# =============================================================================

print_header() {
    local title="$1"
    local width="${2:-60}"
    local line
    line="$(printf '%*s' "${width}" '' | tr ' ' '─')"
    echo -e "\n${BOLD}${CYAN}${line}${NC}"
    echo -e "${BOLD}${WHITE}  ${title}${NC}"
    echo -e "${BOLD}${CYAN}${line}${NC}"
}

print_row() {
    local label="$1"
    local value="$2"
    printf "  ${BOLD}%-20s${NC} %s\n" "${label}:" "${value}"
}

print_separator() {
    local width="${1:-60}"
    printf "  %*s\n" "${width}" '' | tr ' ' '─'
}

print_status() {
    local status="$1"
    local message="$2"
    case "${status}" in
        ok|OK|success)     echo -e "  ${GREEN}✓${NC} ${message}" ;;
        warn|WARNING)      echo -e "  ${YELLOW}⚠${NC} ${message}" ;;
        error|ERROR)       echo -e "  ${RED}✗${NC} ${message}" ;;
        critical|CRITICAL) echo -e "  ${RED}${BOLD}✗ ${message}${NC}" ;;
        info|INFO)         echo -e "  ${BLUE}ℹ${NC} ${message}" ;;
    esac
}

# =============================================================================
# SYSTEM DETECTION
# =============================================================================

detect_firewall() {
    if command -v csf &>/dev/null; then
        echo "csf"
    elif command -v iptables &>/dev/null; then
        echo "iptables"
    elif command -v nft &>/dev/null; then
        echo "nftables"
    else
        echo "none"
    fi
}

detect_webserver() {
    if command -v httpd &>/dev/null || command -v apache2 &>/dev/null; then
        echo "apache"
    elif command -v nginx &>/dev/null; then
        echo "nginx"
    elif command -v litespeed &>/dev/null || [[ -d "/usr/local/lsws" ]]; then
        echo "litespeed"
    else
        echo "unknown"
    fi
}

detect_php() {
    local php_bin=""
    if command -v php &>/dev/null; then
        php_bin="php"
    elif command -v php-cgi &>/dev/null; then
        php_bin="php-cgi"
    elif [[ -f "/usr/local/bin/php" ]]; then
        php_bin="/usr/local/bin/php"
    fi

    if [[ -n "${php_bin}" ]]; then
        "${php_bin}" -v 2>/dev/null | head -1 | grep -oP 'PHP \K[0-9]+\.[0-9]+\.[0-9]+'
    else
        echo "not_found"
    fi
}

is_cpanel() {
    [[ -f "/usr/local/cpanel/version" ]] || [[ -d "/usr/local/cpanel" ]]
}

is_root() {
    [[ "$(id -u)" -eq 0 ]]
}

# =============================================================================
# PROCESS MANAGEMENT
# =============================================================================

get_pid_file() {
    local component="${1:-obsidian}"
    echo "${OBSIDIAN_RUN}/${component}.pid"
}

is_running() {
    local component="${1:-obsidian}"
    local pid_file
    pid_file="$(get_pid_file "${component}")"

    if [[ -f "${pid_file}" ]]; then
        local pid
        pid="$(cat "${pid_file}" 2>/dev/null)"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

write_pid() {
    local component="${1:-obsidian}"
    local pid_file
    pid_file="$(get_pid_file "${component}")"
    mkdir -p "$(dirname "${pid_file}")"
    echo $$ > "${pid_file}"
}

remove_pid() {
    local component="${1:-obsidian}"
    local pid_file
    pid_file="$(get_pid_file "${component}")"
    rm -f "${pid_file}"
}

# =============================================================================
# SIGNAL HANDLING
# =============================================================================

setup_signal_handlers() {
    local cleanup_func="${1:-cleanup}"
    trap "${cleanup_func}" EXIT
    trap "${cleanup_func}; exit 130" INT
    trap "${cleanup_func}; exit 143" TERM
    trap "log_info 'Reloading configuration...'; load_config" HUP
}

# Default cleanup
cleanup() {
    release_lock "${OBSIDIAN_LOCK}" 2>/dev/null || true
    remove_pid 2>/dev/null || true
    log_debug "Cleanup complete"
}

# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

check_dependencies() {
    local -a required=("$@")
    local missing=()

    for cmd in "${required[@]}"; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        return 1
    fi
    return 0
}

# =============================================================================
# DATE/TIME HELPERS
# =============================================================================

epoch_now() {
    date +%s
}

epoch_to_date() {
    date -d "@${1}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown"
}

seconds_ago() {
    local then="$1"
    local now
    now="$(epoch_now)"
    echo $(( now - then ))
}

human_duration() {
    local seconds="$1"
    if [[ "${seconds}" -lt 60 ]]; then
        echo "${seconds}s"
    elif [[ "${seconds}" -lt 3600 ]]; then
        echo "$(( seconds / 60 ))m $(( seconds % 60 ))s"
    elif [[ "${seconds}" -lt 86400 ]]; then
        echo "$(( seconds / 3600 ))h $(( (seconds % 3600) / 60 ))m"
    else
        echo "$(( seconds / 86400 ))d $(( (seconds % 86400) / 3600 ))h"
    fi
}

# =============================================================================
# ENSURE DIRECTORIES EXIST
# =============================================================================

init_directories() {
    mkdir -p "${OBSIDIAN_DATA}" "${OBSIDIAN_LOGS}" "${OBSIDIAN_RUN}" 2>/dev/null || true
    chmod 750 "${OBSIDIAN_DATA}" "${OBSIDIAN_LOGS}" 2>/dev/null || true
}
