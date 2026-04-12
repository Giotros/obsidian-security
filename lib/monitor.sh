#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — File Integrity Monitor
# SHA256 baseline tracking, real-time inotify monitoring, full scans
# Evolved from FileGuard's core monitoring engine
# =============================================================================

readonly BASELINE_FILE="${OBSIDIAN_DATA}/baseline.db"
readonly BASELINE_LOCK="${OBSIDIAN_DATA}/baseline.lock"

# Severity classification by file type/path
declare -A FILE_SEVERITY=(
    ["wp-config.php"]="CRITICAL"
    [".htaccess"]="CRITICAL"
    ["wp-settings.php"]="CRITICAL"
    ["index.php"]="HIGH"
    ["wp-login.php"]="HIGH"
    ["functions.php"]="HIGH"
    ["wp-includes"]="HIGH"
    ["wp-admin"]="HIGH"
    ["xmlrpc.php"]="HIGH"
    [".php"]="MEDIUM"
    [".js"]="MEDIUM"
    [".css"]="LOW"
    [".html"]="LOW"
    [".txt"]="INFO"
)

# =============================================================================
# BASELINE MANAGEMENT
# =============================================================================

generate_baseline() {
    local monitor_path="$1"
    local preset="${2:-}"

    if [[ ! -d "${monitor_path}" ]]; then
        log_error "Path does not exist: ${monitor_path}"
        return 1
    fi

    log_info "Generating baseline for: ${monitor_path}"
    local count=0
    local temp_baseline="${BASELINE_FILE}.tmp"

    acquire_lock "${BASELINE_LOCK}" 30 || return 1

    # Build find command based on preset
    local -a find_args=("${monitor_path}" -type f)

    case "${preset}" in
        wordpress)
            find_args+=(\( -name "*.php" -o -name "*.js" -o -name "*.css" -o -name ".htaccess" -o -name "wp-config.php" \))
            find_args+=(-not -path "*/uploads/*" -not -path "*/cache/*")
            ;;
        woocommerce)
            find_args+=(\( -name "*.php" -o -name "*.js" -o -name "*.css" -o -name ".htaccess" -o -name "wp-config.php" \))
            find_args+=(-not -path "*/uploads/*" -not -path "*/cache/*" -not -path "*/wc-logs/*")
            ;;
        *)
            # Generic: all files except common exclusions
            find_args+=(-not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/cache/*" -not -path "*/tmp/*")
            ;;
    esac

    # Size limit — skip files over 50MB
    find_args+=(-size -50M)

    > "${temp_baseline}"

    while IFS= read -r -d '' filepath; do
        local hash
        hash="$(sha256sum "${filepath}" 2>/dev/null | cut -d' ' -f1)" || continue
        local perms owner size mtime
        perms="$(stat -c '%a' "${filepath}" 2>/dev/null || echo '000')"
        owner="$(stat -c '%U:%G' "${filepath}" 2>/dev/null || echo 'unknown:unknown')"
        size="$(stat -c '%s' "${filepath}" 2>/dev/null || echo '0')"
        mtime="$(stat -c '%Y' "${filepath}" 2>/dev/null || echo '0')"

        # Format: HASH|PATH|PERMISSIONS|OWNER|SIZE|MTIME
        echo "${hash}|${filepath}|${perms}|${owner}|${size}|${mtime}" >> "${temp_baseline}"
        count=$(( count + 1 ))
    done < <(find "${find_args[@]}" -print0 2>/dev/null)

    mv "${temp_baseline}" "${BASELINE_FILE}"
    release_lock "${BASELINE_LOCK}"

    log_info "Baseline generated: ${count} files hashed"
    echo "Baseline: ${count} files in ${monitor_path}"
    return 0
}

# =============================================================================
# INTEGRITY SCANNING
# =============================================================================

full_integrity_scan() {
    local monitor_path="${1:-$(get_config 'monitor_path' '/var/www')}"

    if [[ ! -f "${BASELINE_FILE}" ]]; then
        log_warn "No baseline found. Run 'obsidian scan --baseline' first."
        return 1
    fi

    log_info "Starting full integrity scan: ${monitor_path}"
    local modified=0 deleted=0 new_files=0 permission_changes=0

    # Load baseline into associative arrays
    declare -A baseline_hashes
    declare -A baseline_perms
    declare -A baseline_owners
    declare -A scanned_files

    while IFS='|' read -r hash path perms owner size mtime; do
        [[ -z "${hash}" ]] && continue
        baseline_hashes["${path}"]="${hash}"
        baseline_perms["${path}"]="${perms}"
        baseline_owners["${path}"]="${owner}"
    done < "${BASELINE_FILE}"

    # Scan current files
    while IFS= read -r -d '' filepath; do
        scanned_files["${filepath}"]=1

        local current_hash
        current_hash="$(sha256sum "${filepath}" 2>/dev/null | cut -d' ' -f1)" || continue
        local current_perms
        current_perms="$(stat -c '%a' "${filepath}" 2>/dev/null || echo '000')"
        local current_owner
        current_owner="$(stat -c '%U:%G' "${filepath}" 2>/dev/null || echo 'unknown:unknown')"

        if [[ -z "${baseline_hashes[${filepath}]+x}" ]]; then
            # New file — not in baseline
            new_files=$(( new_files + 1 ))
            local severity
            severity="$(classify_severity "${filepath}")"
            log_warn "New file detected: ${filepath}"

            send_alert "${severity}" "FileGuard" "New File" \
                "New file detected: ${filepath}\nPermissions: ${current_perms}\nOwner: ${current_owner}" &
        else
            # Existing file — check hash
            if [[ "${current_hash}" != "${baseline_hashes[${filepath}]}" ]]; then
                modified=$(( modified + 1 ))
                local severity
                severity="$(classify_severity "${filepath}")"
                log_warn "File modified: ${filepath}"

                send_alert "${severity}" "FileGuard" "File Modified" \
                    "File content changed: ${filepath}\nOld hash: ${baseline_hashes[${filepath}]:0:16}...\nNew hash: ${current_hash:0:16}..." &
            fi

            # Check permissions
            if [[ "${current_perms}" != "${baseline_perms[${filepath}]:-}" ]]; then
                permission_changes=$(( permission_changes + 1 ))
                log_warn "Permission change: ${filepath} (${baseline_perms[${filepath}]} → ${current_perms})"

                send_alert "MEDIUM" "FileGuard" "Permission Change" \
                    "File permissions changed: ${filepath}\nOld: ${baseline_perms[${filepath}]}\nNew: ${current_perms}" &
            fi

            # Check ownership
            if [[ "${current_owner}" != "${baseline_owners[${filepath}]:-}" ]]; then
                log_warn "Ownership change: ${filepath} (${baseline_owners[${filepath}]} → ${current_owner})"

                send_alert "HIGH" "FileGuard" "Ownership Change" \
                    "File ownership changed: ${filepath}\nOld: ${baseline_owners[${filepath}]}\nNew: ${current_owner}" &
            fi
        fi
    done < <(find "${monitor_path}" -type f -not -path "*/uploads/*" -not -path "*/cache/*" -size -50M -print0 2>/dev/null)

    # Check for deleted files
    for path in "${!baseline_hashes[@]}"; do
        if [[ -z "${scanned_files[${path}]+x}" ]]; then
            deleted=$(( deleted + 1 ))
            local severity
            severity="$(classify_severity "${path}")"
            log_warn "File deleted: ${path}"

            send_alert "${severity}" "FileGuard" "File Deleted" \
                "File removed from disk: ${path}" &
        fi
    done

    wait  # Wait for async alerts

    local total_issues=$(( modified + deleted + new_files + permission_changes ))
    log_info "Scan complete: ${modified} modified, ${deleted} deleted, ${new_files} new, ${permission_changes} permission changes"

    # Print summary
    print_header "Integrity Scan Results"
    print_row "Modified files" "${modified}"
    print_row "Deleted files" "${deleted}"
    print_row "New files" "${new_files}"
    print_row "Permission changes" "${permission_changes}"
    print_separator
    if [[ "${total_issues}" -eq 0 ]]; then
        print_status "ok" "All files match baseline — integrity verified"
    else
        print_status "warn" "${total_issues} issue(s) detected"
    fi

    return "${total_issues}"
}

# =============================================================================
# REAL-TIME MONITORING (inotifywait)
# =============================================================================

start_realtime_monitor() {
    local monitor_path="${1:-$(get_config 'monitor_path' '/var/www')}"

    if ! command -v inotifywait &>/dev/null; then
        log_error "inotifywait not found. Install: apt install inotify-tools"
        return 1
    fi

    log_info "Starting real-time file monitor: ${monitor_path}"

    # Monitor for: modify, create, delete, move, attrib changes
    inotifywait -m -r \
        --format '%T|%w%f|%e' \
        --timefmt '%Y-%m-%d %H:%M:%S' \
        -e modify,create,delete,move,attrib \
        --exclude '(\.swp|\.tmp|~$|/cache/|/uploads/|\.log$)' \
        "${monitor_path}" 2>/dev/null | while IFS='|' read -r timestamp filepath events; do

        # Skip empty
        [[ -z "${filepath}" ]] && continue

        # Skip non-critical file types in real-time (reduce noise)
        case "${filepath}" in
            *.log|*.tmp|*.swp|*.bak) continue ;;
        esac

        local severity
        severity="$(classify_severity "${filepath}")"
        local event_type
        event_type="$(echo "${events}" | tr ',' ' ')"

        log_info "File event: ${event_type} — ${filepath}"

        # Process the event
        process_file_event "${timestamp}" "${filepath}" "${event_type}" "${severity}"
    done
}

process_file_event() {
    local timestamp="$1"
    local filepath="$2"
    local event_type="$3"
    local severity="$4"

    # Check if this is a whitelisted change (admin editing via cPanel etc.)
    # This is done via IP correlation
    local suspect_ip=""
    if type correlate_ip &>/dev/null; then
        suspect_ip="$(correlate_ip "${filepath}" "${timestamp}" 2>/dev/null || echo "")"
    fi

    if [[ -n "${suspect_ip}" ]] && is_whitelisted "${suspect_ip}"; then
        log_debug "File change by whitelisted IP ${suspect_ip}: ${filepath}"
        return 0
    fi

    local message="Event: ${event_type}\nFile: ${filepath}\nTime: ${timestamp}"
    if [[ -n "${suspect_ip}" ]]; then
        message="${message}\nSuspect IP: ${suspect_ip}"
    fi

    send_alert "${severity}" "FileGuard" "File ${event_type}" "${message}" &

    # If critical file changed by unknown IP, consider auto-ban
    if [[ "${severity}" == "CRITICAL" ]] && [[ -n "${suspect_ip}" ]] && ! is_whitelisted "${suspect_ip}"; then
        local auto_ban
        auto_ban="$(get_config 'auto_ban_critical' 'false')"
        if [[ "${auto_ban}" == "true" ]]; then
            log_warn "Auto-banning IP ${suspect_ip} for critical file modification: ${filepath}"
            ban_ip "${suspect_ip}" "Critical file modified: ${filepath}" "fileguard" "correlate"
        fi
    fi
}

# =============================================================================
# SEVERITY CLASSIFICATION
# =============================================================================

classify_severity() {
    local filepath="$1"
    local filename
    filename="$(basename "${filepath}")"

    # Check exact filename matches first
    for pattern in "${!FILE_SEVERITY[@]}"; do
        if [[ "${filename}" == "${pattern}" ]]; then
            echo "${FILE_SEVERITY[${pattern}]}"
            return
        fi
    done

    # Check path contains
    for pattern in "${!FILE_SEVERITY[@]}"; do
        if [[ "${filepath}" == *"${pattern}"* ]]; then
            echo "${FILE_SEVERITY[${pattern}]}"
            return
        fi
    done

    # Default based on extension
    case "${filename}" in
        *.php)  echo "MEDIUM" ;;
        *.js)   echo "MEDIUM" ;;
        *.sh)   echo "HIGH" ;;
        *.py)   echo "HIGH" ;;
        *.cgi)  echo "HIGH" ;;
        *.conf) echo "MEDIUM" ;;
        *)      echo "LOW" ;;
    esac
}

# =============================================================================
# VERIFY SINGLE FILE
# =============================================================================

verify_file() {
    local filepath="$1"

    if [[ ! -f "${filepath}" ]]; then
        echo -e "${RED}File not found: ${filepath}${NC}"
        return 1
    fi

    if [[ ! -f "${BASELINE_FILE}" ]]; then
        echo "No baseline available for comparison."
        return 1
    fi

    local current_hash
    current_hash="$(sha256sum "${filepath}" | cut -d' ' -f1)"
    local baseline_entry
    baseline_entry="$(grep "|${filepath}|" "${BASELINE_FILE}" 2>/dev/null | head -1)"

    if [[ -z "${baseline_entry}" ]]; then
        echo -e "${YELLOW}File not in baseline: ${filepath}${NC}"
        echo "Current hash: ${current_hash}"
        return 2
    fi

    local baseline_hash
    baseline_hash="$(echo "${baseline_entry}" | cut -d'|' -f1)"

    print_header "File Verification: $(basename "${filepath}")"
    print_row "Path" "${filepath}"
    print_row "Current hash" "${current_hash:0:32}..."
    print_row "Baseline hash" "${baseline_hash:0:32}..."

    if [[ "${current_hash}" == "${baseline_hash}" ]]; then
        print_status "ok" "File integrity verified — matches baseline"
        return 0
    else
        print_status "error" "MISMATCH — file has been modified since baseline"
        return 1
    fi
}
