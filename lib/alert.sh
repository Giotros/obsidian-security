#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Alert System
# Multi-channel alerts: Telegram, Webhook, Email
# Deduplication, rate limiting, daily digest
# =============================================================================

# Alert deduplication tracking
declare -A ALERT_LAST_SENT
ALERT_COUNT=0
ALERT_MAX_PER_MINUTE="${ALERT_MAX_PER_MINUTE:-30}"
ALERT_COOLDOWN="${ALERT_COOLDOWN:-300}"  # 5 min between same alerts

# =============================================================================
# SEVERITY LEVELS
# =============================================================================

readonly SEVERITY_CRITICAL="CRITICAL"
readonly SEVERITY_HIGH="HIGH"
readonly SEVERITY_MEDIUM="MEDIUM"
readonly SEVERITY_LOW="LOW"
readonly SEVERITY_INFO="INFO"

severity_emoji() {
    case "$1" in
        CRITICAL) echo "🔴" ;;
        HIGH)     echo "🟠" ;;
        MEDIUM)   echo "🟡" ;;
        LOW)      echo "🔵" ;;
        INFO)     echo "ℹ️" ;;
        *)        echo "⚪" ;;
    esac
}

severity_to_number() {
    case "$1" in
        CRITICAL) echo 4 ;;
        HIGH)     echo 3 ;;
        MEDIUM)   echo 2 ;;
        LOW)      echo 1 ;;
        INFO)     echo 0 ;;
        *)        echo 0 ;;
    esac
}

# =============================================================================
# ALERT DEDUPLICATION
# =============================================================================

should_send_alert() {
    local alert_key="$1"
    local now
    now="$(epoch_now)"

    # Rate limiting — max alerts per minute
    if [[ "${ALERT_COUNT}" -ge "${ALERT_MAX_PER_MINUTE}" ]]; then
        log_warn "Alert rate limit reached (${ALERT_MAX_PER_MINUTE}/min)"
        return 1
    fi

    # Deduplication — same alert within cooldown period
    local last_sent="${ALERT_LAST_SENT[${alert_key}]:-0}"
    local elapsed=$(( now - last_sent ))

    if [[ "${elapsed}" -lt "${ALERT_COOLDOWN}" ]]; then
        log_debug "Alert deduplicated (${elapsed}s < ${ALERT_COOLDOWN}s cooldown): ${alert_key}"
        return 1
    fi

    ALERT_LAST_SENT["${alert_key}"]="${now}"
    ALERT_COUNT=$(( ALERT_COUNT + 1 ))
    return 0
}

# Reset alert counter (call this every minute from the main loop)
reset_alert_counter() {
    ALERT_COUNT=0
}

# =============================================================================
# SEND ALERT (unified entry point)
# =============================================================================

send_alert() {
    local severity="$1"
    local module="$2"
    local title="$3"
    local message="$4"
    local details="${5:-}"

    # Build alert key for deduplication
    local alert_key="${module}:${title}:${message%%$'\n'*}"

    # Check minimum severity
    local min_severity
    min_severity="$(get_config 'alert_min_severity' 'MEDIUM')"
    if [[ "$(severity_to_number "${severity}")" -lt "$(severity_to_number "${min_severity}")" ]]; then
        log_debug "Alert below minimum severity (${severity} < ${min_severity}): ${title}"
        return 0
    fi

    # Deduplication check
    if ! should_send_alert "${alert_key}"; then
        return 0
    fi

    local hostname
    hostname="$(hostname -f 2>/dev/null || hostname)"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Log the alert
    log_info "[ALERT] [${severity}] [${module}] ${title}: ${message}"

    # Save to alert history
    save_alert_history "${severity}" "${module}" "${title}" "${message}"

    # Send to all configured channels
    local telegram_token
    telegram_token="$(get_config 'telegram_bot_token' '')"
    local telegram_chat
    telegram_chat="$(get_config 'telegram_chat_id' '')"
    if [[ -n "${telegram_token}" ]] && [[ -n "${telegram_chat}" ]]; then
        send_telegram_alert "${severity}" "${module}" "${title}" "${message}" "${hostname}" "${timestamp}" "${details}" &
    fi

    local webhook_url
    webhook_url="$(get_config 'webhook_url' '')"
    if [[ -n "${webhook_url}" ]]; then
        send_webhook_alert "${severity}" "${module}" "${title}" "${message}" "${hostname}" "${timestamp}" "${details}" &
    fi

    local email_to
    email_to="$(get_config 'alert_email' '')"
    if [[ -n "${email_to}" ]]; then
        send_email_alert "${severity}" "${module}" "${title}" "${message}" "${hostname}" "${timestamp}" "${details}" &
    fi

    # Wait for background sends (with timeout)
    wait
}

# =============================================================================
# TELEGRAM
# =============================================================================

send_telegram_alert() {
    local severity="$1" module="$2" title="$3" message="$4"
    local hostname="$5" timestamp="$6" details="${7:-}"

    local token
    token="$(get_config 'telegram_bot_token' '')"
    local chat_id
    chat_id="$(get_config 'telegram_chat_id' '')"

    [[ -z "${token}" ]] || [[ -z "${chat_id}" ]] && return 1

    local emoji
    emoji="$(severity_emoji "${severity}")"

    local text="${emoji} *Obsidian Alert — ${severity}*

*Server:* \`${hostname}\`
*Module:* ${module}
*Alert:* ${title}
*Time:* ${timestamp}

${message}"

    if [[ -n "${details}" ]]; then
        text="${text}

\`\`\`
${details}
\`\`\`"
    fi

    local escaped_text
    escaped_text="$(json_escape "${text}")"

    retry_with_backoff 3 2 curl -s --max-time 10 \
        -X POST "https://api.telegram.org/bot${token}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\":\"${chat_id}\",\"text\":\"${escaped_text}\",\"parse_mode\":\"Markdown\",\"disable_web_page_preview\":true}" \
        >/dev/null 2>&1

    log_debug "Telegram alert sent: ${title}"
}

# =============================================================================
# WEBHOOK
# =============================================================================

send_webhook_alert() {
    local severity="$1" module="$2" title="$3" message="$4"
    local hostname="$5" timestamp="$6" details="${7:-}"

    local url
    url="$(get_config 'webhook_url' '')"
    [[ -z "${url}" ]] && return 1

    local webhook_secret
    webhook_secret="$(get_config 'webhook_secret' '')"

    local payload
    payload="{
        \"severity\": \"${severity}\",
        \"module\": \"$(json_escape "${module}")\",
        \"title\": \"$(json_escape "${title}")\",
        \"message\": \"$(json_escape "${message}")\",
        \"details\": \"$(json_escape "${details}")\",
        \"hostname\": \"$(json_escape "${hostname}")\",
        \"timestamp\": \"${timestamp}\",
        \"source\": \"obsidian\",
        \"version\": \"${OBSIDIAN_VERSION}\"
    }"

    local -a curl_args=(
        -s --max-time 15
        -X POST "${url}"
        -H "Content-Type: application/json"
        -H "X-Obsidian-Event: alert"
    )

    # HMAC signature if secret configured
    if [[ -n "${webhook_secret}" ]]; then
        local signature
        signature="$(echo -n "${payload}" | openssl dgst -sha256 -hmac "${webhook_secret}" -hex 2>/dev/null | awk '{print $NF}')"
        curl_args+=(-H "X-Obsidian-Signature: sha256=${signature}")
    fi

    curl_args+=(-d "${payload}")

    retry_with_backoff 3 2 curl "${curl_args[@]}" >/dev/null 2>&1

    log_debug "Webhook alert sent: ${title}"
}

# =============================================================================
# EMAIL
# =============================================================================

send_email_alert() {
    local severity="$1" module="$2" title="$3" message="$4"
    local hostname="$5" timestamp="$6" details="${7:-}"

    local email_to
    email_to="$(get_config 'alert_email' '')"
    [[ -z "${email_to}" ]] && return 1

    local subject="[Obsidian ${severity}] ${title} — ${hostname}"

    local body="Obsidian Security Alert
═══════════════════════════════════

Severity:  ${severity}
Server:    ${hostname}
Module:    ${module}
Alert:     ${title}
Time:      ${timestamp}

${message}"

    if [[ -n "${details}" ]]; then
        body="${body}

Details:
────────
${details}"
    fi

    body="${body}

───────────────────────────────
Obsidian Security Suite v${OBSIDIAN_VERSION}
"

    if command -v mail &>/dev/null; then
        echo "${body}" | mail -s "${subject}" "${email_to}" 2>/dev/null
        log_debug "Email alert sent to ${email_to}: ${title}"
    elif command -v sendmail &>/dev/null; then
        {
            echo "To: ${email_to}"
            echo "Subject: ${subject}"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo "${body}"
        } | sendmail -t 2>/dev/null
        log_debug "Email alert sent via sendmail to ${email_to}: ${title}"
    else
        log_warn "No mail command available, email alert skipped"
        return 1
    fi
}

# =============================================================================
# ALERT HISTORY
# =============================================================================

save_alert_history() {
    local severity="$1" module="$2" title="$3" message="$4"
    local history_file="${OBSIDIAN_DATA}/alert_history.log"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    echo "${timestamp}|${severity}|${module}|${title}|${message}" >> "${history_file}" 2>/dev/null || true

    # Rotate if too large (keep last 10000 entries)
    if [[ -f "${history_file}" ]]; then
        local line_count
        line_count="$(wc -l < "${history_file}" 2>/dev/null || echo 0)"
        if [[ "${line_count}" -gt 10000 ]]; then
            tail -5000 "${history_file}" > "${history_file}.tmp" && \
                mv "${history_file}.tmp" "${history_file}"
        fi
    fi
}

show_alert_history() {
    local count="${1:-20}"
    local history_file="${OBSIDIAN_DATA}/alert_history.log"

    if [[ ! -f "${history_file}" ]]; then
        echo "No alert history found."
        return
    fi

    print_header "Alert History (last ${count})"
    echo ""

    tail -"${count}" "${history_file}" | while IFS='|' read -r timestamp severity module title message; do
        local emoji
        emoji="$(severity_emoji "${severity}")"
        printf "  %s %-8s [%-10s] %-30s %s\n" "${emoji}" "${severity}" "${module}" "${title}" "${timestamp}"
    done

    echo ""
    local total
    total="$(wc -l < "${history_file}" 2>/dev/null || echo 0)"
    echo -e "  Total alerts recorded: ${BOLD}${total}${NC}"
}

# =============================================================================
# TEST ALERT
# =============================================================================

send_test_alert() {
    log_info "Sending test alert to all configured channels..."
    send_alert "INFO" "System" "Test Alert" \
        "This is a test alert from Obsidian Security Suite. If you received this, your alert configuration is working correctly." \
        "Hostname: $(hostname)\nTime: $(date)\nVersion: ${OBSIDIAN_VERSION}"
}
