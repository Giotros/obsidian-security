#!/usr/bin/env bash
# =============================================================================
# Obsidian Security Suite — Security Audit Module
# Runs ALL security checks and produces structured JSON output
# for PDF report generation
#
# Usage: obsidian audit [--path /home] [--output report.json]
# =============================================================================

readonly AUDIT_DIR="${OBSIDIAN_DATA}/audits"

# =============================================================================
# AUDIT DATA COLLECTION (JSON output for report generator)
# =============================================================================

run_full_audit() {
    local scan_path="${1:-/home}"
    local output_file="${2:-}"
    local audit_id
    audit_id="audit_$(date '+%Y%m%d_%H%M%S')"

    mkdir -p "${AUDIT_DIR}"

    local audit_json="${AUDIT_DIR}/${audit_id}.json"
    local hostname
    hostname="$(hostname -f 2>/dev/null || hostname)"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local start_time
    start_time="$(date +%s)"

    echo -e "\n${BOLD}${CYAN}Obsidian Security Audit${NC}"
    echo -e "${CYAN}══════════════════════════════════════${NC}"
    echo -e "  Server:    ${hostname}"
    echo -e "  Scan path: ${scan_path}"
    echo -e "  Audit ID:  ${audit_id}"
    echo -e "  Started:   ${timestamp}"
    echo -e "${CYAN}══════════════════════════════════════${NC}\n"

    # Initialize JSON
    local json="{"
    json+="\"audit_id\":\"${audit_id}\","
    json+="\"hostname\":\"$(json_escape "${hostname}")\","
    json+="\"timestamp\":\"${timestamp}\","
    json+="\"scan_path\":\"$(json_escape "${scan_path}")\","
    json+="\"obsidian_version\":\"${OBSIDIAN_VERSION}\","

    # --- System Info ---
    echo -e "${BOLD}[1/7] Collecting system information...${NC}"
    local os_info="Unknown"
    [[ -f /etc/os-release ]] && os_info="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
    local kernel
    kernel="$(uname -r 2>/dev/null || echo 'unknown')"
    local uptime_str
    uptime_str="$(uptime -p 2>/dev/null || echo 'unknown')"
    local cpu_cores
    cpu_cores="$(nproc 2>/dev/null || echo '?')"
    local mem_total_mb
    mem_total_mb="$(( $(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0) / 1024 ))"
    local webserver
    webserver="$(detect_webserver)"
    local firewall
    firewall="$(detect_firewall)"
    local php_ver
    php_ver="$(detect_php)"
    local cpanel_ver="N/A"
    [[ -f "/usr/local/cpanel/version" ]] && cpanel_ver="$(cat /usr/local/cpanel/version 2>/dev/null)"

    json+="\"system\":{\"os\":\"$(json_escape "${os_info}")\",\"kernel\":\"${kernel}\",\"uptime\":\"$(json_escape "${uptime_str}")\",\"cpu_cores\":${cpu_cores},\"memory_mb\":${mem_total_mb},\"webserver\":\"${webserver}\",\"firewall\":\"${firewall}\",\"php_version\":\"${php_ver}\",\"cpanel\":\"${cpanel_ver}\"},"
    print_status "ok" "System info collected"

    # --- Health Metrics ---
    echo -e "\n${BOLD}[2/7] Checking system health...${NC}"
    local cpu_usage
    cpu_usage="$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{printf "%.0f", 100 - $8}' || echo 0)"
    local mem_total mem_avail mem_percent
    mem_total="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
    mem_avail="$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
    [[ "${mem_total}" -gt 0 ]] && mem_percent=$(( ((mem_total - mem_avail) * 100) / mem_total )) || mem_percent=0
    local disk_percent
    disk_percent="$(df / 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%' || echo 0)"
    local disk_avail
    disk_avail="$(df -h / 2>/dev/null | tail -1 | awk '{print $4}' || echo '?')"
    local load_avg
    load_avg="$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}' || echo '0 0 0')"

    local health_score=100
    local health_issues="["
    local first_issue=true

    add_issue() {
        local sev="$1" cat="$2" title="$3" desc="$4" rec="$5"
        [[ "${first_issue}" == true ]] && first_issue=false || health_issues+=","
        health_issues+="{\"severity\":\"${sev}\",\"category\":\"$(json_escape "${cat}")\",\"title\":\"$(json_escape "${title}")\",\"description\":\"$(json_escape "${desc}")\",\"recommendation\":\"$(json_escape "${rec}")\"}"
        case "${sev}" in
            CRITICAL) health_score=$(( health_score - 20 )) ;;
            HIGH)     health_score=$(( health_score - 10 )) ;;
            MEDIUM)   health_score=$(( health_score - 5 )) ;;
            LOW)      health_score=$(( health_score - 2 )) ;;
        esac
    }

    # CPU check
    if [[ "${cpu_usage}" -ge 95 ]]; then
        add_issue "CRITICAL" "Resources" "CPU Critical" "CPU usage at ${cpu_usage}%" "Investigate high-CPU processes. Check for cryptominers."
        print_status "critical" "CPU: ${cpu_usage}%"
    elif [[ "${cpu_usage}" -ge 80 ]]; then
        add_issue "MEDIUM" "Resources" "CPU High" "CPU usage at ${cpu_usage}%" "Monitor CPU usage. Consider upgrading or optimizing."
        print_status "warn" "CPU: ${cpu_usage}%"
    else
        print_status "ok" "CPU: ${cpu_usage}%"
    fi

    # Memory check
    if [[ "${mem_percent}" -ge 95 ]]; then
        add_issue "CRITICAL" "Resources" "Memory Critical" "Memory usage at ${mem_percent}%" "Add RAM or optimize applications. Check for memory leaks."
        print_status "critical" "Memory: ${mem_percent}%"
    elif [[ "${mem_percent}" -ge 80 ]]; then
        add_issue "MEDIUM" "Resources" "Memory High" "Memory usage at ${mem_percent}%" "Monitor memory usage. Consider adding swap or RAM."
        print_status "warn" "Memory: ${mem_percent}%"
    else
        print_status "ok" "Memory: ${mem_percent}%"
    fi

    # Disk check
    if [[ "${disk_percent}" -ge 90 ]]; then
        add_issue "CRITICAL" "Resources" "Disk Space Critical" "Disk usage at ${disk_percent}% (${disk_avail} available)" "Free up disk space immediately. Remove old logs, backups, cache files."
        print_status "critical" "Disk: ${disk_percent}%"
    elif [[ "${disk_percent}" -ge 80 ]]; then
        add_issue "HIGH" "Resources" "Disk Space Warning" "Disk usage at ${disk_percent}% (${disk_avail} available)" "Plan disk cleanup. Monitor growth rate."
        print_status "warn" "Disk: ${disk_percent}%"
    else
        print_status "ok" "Disk: ${disk_percent}% (${disk_avail} free)"
    fi

    # PHP check
    if [[ "${php_ver}" != "not_found" ]]; then
        local php_major="${php_ver%%.*}"
        local php_minor="${php_ver#*.}"; php_minor="${php_minor%%.*}"
        if [[ "${php_major}" -le 7 ]]; then
            add_issue "CRITICAL" "Software" "PHP End-of-Life" "PHP ${php_ver} is no longer receiving security updates" "Upgrade to PHP 8.1 or later immediately. PHP 7.x has known vulnerabilities."
            print_status "critical" "PHP ${php_ver} — END OF LIFE"
        elif [[ "${php_major}" -eq 8 ]] && [[ "${php_minor}" -eq 0 ]]; then
            add_issue "HIGH" "Software" "PHP Version Outdated" "PHP 8.0 is end-of-life" "Upgrade to PHP 8.1+ for security patches."
            print_status "warn" "PHP ${php_ver} — EOL"
        else
            print_status "ok" "PHP ${php_ver}"
        fi
    fi

    # PHP config check (extMaxIdleTime)
    if [[ -f "/usr/local/lsws/conf/httpd_config.xml" ]]; then
        local idle_time
        idle_time="$(grep -oP 'extMaxIdleTime>\K[0-9]+' /usr/local/lsws/conf/httpd_config.xml 2>/dev/null || echo "")"
        if [[ -n "${idle_time}" ]] && [[ "${idle_time}" -lt 30 ]]; then
            add_issue "HIGH" "Configuration" "PHP Aggressive Recycling" "extMaxIdleTime=${idle_time}s causes frequent PHP process restarts and 503 errors" "Increase extMaxIdleTime to 60-300 seconds."
            print_status "critical" "extMaxIdleTime=${idle_time}s — too low!"
        fi
    fi

    json+="\"health\":{\"cpu_percent\":${cpu_usage},\"memory_percent\":${mem_percent},\"disk_percent\":${disk_percent},\"disk_available\":\"${disk_avail}\",\"load_average\":\"${load_avg}\"},"

    # --- Malware Scan ---
    echo -e "\n${BOLD}[3/7] Scanning for malware & cryptominers...${NC}"

    local malware_findings="["
    local first_malware=true

    add_malware() {
        local type="$1" path="$2" detail="$3"
        [[ "${first_malware}" == true ]] && first_malware=false || malware_findings+=","
        malware_findings+="{\"type\":\"$(json_escape "${type}")\",\"path\":\"$(json_escape "${path}")\",\"detail\":\"$(json_escape "${detail}")\"}"
    }

    # Hidden executables
    local hidden_count=0
    while IFS= read -r -d '' file; do
        if file "${file}" 2>/dev/null | grep -qiE '(ELF|executable|shared object)'; then
            hidden_count=$(( hidden_count + 1 ))
            local fowner
            fowner="$(stat -c '%U' "${file}" 2>/dev/null || echo 'unknown')"
            add_malware "hidden_binary" "${file}" "Owner: ${fowner}"
            add_issue "CRITICAL" "Malware" "Hidden Executable Binary" "Found: ${file} (owner: ${fowner})" "Kill associated processes, delete the file, check for persistence (cron jobs)."
            print_status "critical" "Hidden binary: ${file}"
        fi
    done < <(find "${scan_path}" -path '*/.*/*' -type f -executable -print0 2>/dev/null)
    [[ "${hidden_count}" -eq 0 ]] && print_status "ok" "No hidden executables"

    # Web shells
    local webshell_count=0
    local webshell_pattern='eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate|eval\s*\(\s*\$_(GET|POST|REQUEST)|system\s*\(\s*\$_|shell_exec\s*\(\s*\$_|passthru\s*\(\s*\$_|assert\s*\(\s*\$_|c99shell|r57shell|b374k|FilesMan'
    while IFS= read -r -d '' php_file; do
        if grep -lqP "${webshell_pattern}" "${php_file}" 2>/dev/null; then
            webshell_count=$(( webshell_count + 1 ))
            add_malware "webshell" "${php_file}" "$(grep -nP "${webshell_pattern}" "${php_file}" 2>/dev/null | head -1 | cut -c1-150)"
            add_issue "CRITICAL" "Malware" "PHP Web Shell Detected" "Found in: ${php_file}" "Delete immediately. Check access logs for the upload source IP. Scan for additional shells."
            print_status "critical" "Web shell: $(basename "${php_file}")"
        fi
    done < <(find "${scan_path}" -name "*.php" -type f -size -5M -print0 2>/dev/null)
    [[ "${webshell_count}" -eq 0 ]] && print_status "ok" "No web shells detected"

    # Suspicious crons
    local cron_count=0
    local cron_pattern='(curl|wget).*\|.*(sh|bash)|base64.*decode|eval|/\.\w+/|/\.cache/|/tmp/\.'
    for cron_file in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/cron.d/*; do
        [[ -f "${cron_file}" ]] || continue
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            [[ "${line}" =~ ^# ]] && continue
            if echo "${line}" | grep -qE "${cron_pattern}"; then
                cron_count=$(( cron_count + 1 ))
                add_malware "malicious_cron" "${cron_file}" "${line:0:200}"
                add_issue "CRITICAL" "Malware" "Suspicious Cron Job" "In ${cron_file}: ${line:0:100}" "Remove the cron entry. Kill associated processes. Check for reinfection mechanism."
                print_status "critical" "Suspicious cron in $(basename "${cron_file}")"
            fi
        done < "${cron_file}"
    done

    # Also check user crontabs via crontab -l
    local users
    users="$(awk -F: '$3 >= 500 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null)"
    for user in ${users}; do
        local ucron
        ucron="$(crontab -l -u "${user}" 2>/dev/null)" || continue
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            [[ "${line}" =~ ^# ]] && continue
            if echo "${line}" | grep -qE "${cron_pattern}"; then
                cron_count=$(( cron_count + 1 ))
                add_malware "malicious_cron" "crontab:${user}" "${line:0:200}"
                add_issue "CRITICAL" "Malware" "Suspicious Cron Job" "User ${user}: ${line:0:100}" "Remove the cron entry immediately."
                print_status "critical" "Suspicious cron for user: ${user}"
            fi
        done <<< "${ucron}"
    done
    [[ "${cron_count}" -eq 0 ]] && print_status "ok" "No suspicious cron jobs"

    # Suspicious processes
    local proc_count=0
    local proc_pattern='(xmrig|cryptonight|stratum|minerd|lib-update|\.cache.*lib|coin.*mine)'
    while IFS= read -r line; do
        local pcmd
        pcmd="$(echo "${line}" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i}')"
        if echo "${pcmd}" | grep -qiE "${proc_pattern}"; then
            proc_count=$(( proc_count + 1 ))
            local ppid puser pcpu pmem
            puser="$(echo "${line}" | awk '{print $1}')"
            ppid="$(echo "${line}" | awk '{print $2}')"
            pcpu="$(echo "${line}" | awk '{print $3}')"
            pmem="$(echo "${line}" | awk '{print $4}')"
            add_malware "suspicious_process" "PID:${ppid}" "User:${puser} CPU:${pcpu}% CMD:${pcmd:0:150}"
            add_issue "CRITICAL" "Malware" "Suspicious Process Running" "PID ${ppid} (${puser}): ${pcmd:0:80}" "Kill process: kill -9 ${ppid}. Find and remove the binary. Check cron for persistence."
            print_status "critical" "Suspicious process PID ${ppid}"
        fi
    done < <(ps aux --no-headers 2>/dev/null)
    [[ "${proc_count}" -eq 0 ]] && print_status "ok" "No suspicious processes"

    malware_findings+="]"
    json+="\"malware\":${malware_findings},"

    # --- Bot Analysis ---
    echo -e "\n${BOLD}[4/7] Analyzing bot traffic...${NC}"
    local bot_findings="["
    local first_bot=true
    local total_bot_ips=0

    # Bot family classification — maps bot name to family + description
    # Families: ddos_botnet, ai_crawler, seo_crawler, vuln_scanner, scraper, generic
    classify_bot_family() {
        local bot_name="${1,,}"  # lowercase
        case "${bot_name}" in
            *bytespider*|*petalbot*)
                echo "ai_crawler|AI Training Crawler|Aggressive crawlers collecting data for AI/LLM training. Originate from ByteDance (China) and Huawei. Known for ignoring robots.txt and generating massive request volumes.";;
            *gptbot*|*ccbot*|*claudebot*|*anthropic*|*perplexity*|*cohere*)
                echo "ai_crawler|AI Training Crawler|Crawlers for AI companies collecting training data. Some respect robots.txt, others do not.";;
            *ahrefsbot*|*semrushbot*|*mj12bot*|*dotbot*|*blexbot*|*dataforseobot*|*serpstatbot*|*rogerbot*|*screaming*)
                echo "seo_crawler|SEO Crawler|Commercial SEO tool crawlers indexing your site for competitor analysis. High request volumes, limited value to site owner.";;
            *nikto*|*sqlmap*|*nmap*|*dirbuster*|*gobuster*|*wpscan*|*nuclei*|*masscan*|*zgrab*|*joomla*scanner*)
                echo "vuln_scanner|Vulnerability Scanner|Active security scanning tools probing for known vulnerabilities, exposed files, SQL injection, XSS, etc. May indicate reconnaissance for an attack.";;
            *python-requests*|*go-http-client*|*curl*|*wget*|*libwww-perl*|*phantomjs*|*headlesschrome*|*scrapy*|*httpclient*)
                echo "scraper|Scraper / Generic Bot|Generic HTTP libraries often used in automated scraping, credential stuffing, or botnet C2 communication. Legitimate use is possible but uncommon at high volumes.";;
            *sogou*)
                echo "seo_crawler|Chinese Search Crawler|Sogou search engine crawler. Typically aggressive and of limited value outside China.";;
            *yandexbot*)
                echo "seo_crawler|Russian Search Crawler|Yandex search engine crawler. Can be aggressive and is of limited value outside Russia/CIS.";;
            *)
                echo "generic|Unknown Bot Family|Unclassified bot or custom User-Agent. Review access patterns to determine intent.";;
        esac
    }

    local access_log=""
    for path in /var/log/apache2/access.log /var/log/httpd/access_log /usr/local/apache/logs/access_log /var/log/nginx/access.log; do
        [[ -f "${path}" ]] && access_log="${path}" && break
    done

    # Track per-family totals for summary
    declare -A family_totals
    declare -A family_labels

    if [[ -n "${access_log}" ]]; then
        local bad_bot_patterns="Bytespider|AhrefsBot|SemrushBot|MJ12bot|DotBot|PetalBot|BLEXBot|DataForSeoBot|nikto|sqlmap|masscan|zgrab|Nuclei|wpscan|python-requests|Go-http-client|GPTBot|CCBot|Sogou|YandexBot|ClaudeBot|Anthropic|Scrapy"

        # Count by bot type
        while IFS= read -r bot_line; do
            local bot_count bot_name
            bot_count="$(echo "${bot_line}" | awk '{print $1}')"
            bot_name="$(echo "${bot_line}" | awk '{$1=""; print $0}' | xargs)"
            [[ -z "${bot_count}" ]] && continue
            [[ "${bot_count}" -lt 5 ]] && continue

            # Classify into family
            local family_info family_id family_label family_desc
            family_info="$(classify_bot_family "${bot_name}")"
            family_id="$(echo "${family_info}" | cut -d'|' -f1)"
            family_label="$(echo "${family_info}" | cut -d'|' -f2)"
            family_desc="$(echo "${family_info}" | cut -d'|' -f3)"

            family_totals["${family_id}"]=$(( ${family_totals["${family_id}"]:-0} + bot_count ))
            family_labels["${family_id}"]="${family_label}"

            total_bot_ips=$(( total_bot_ips + bot_count ))
            [[ "${first_bot}" == true ]] && first_bot=false || bot_findings+=","
            bot_findings+="{\"pattern\":\"$(json_escape "${bot_name}")\",\"hits\":${bot_count},\"family\":\"${family_id}\",\"family_label\":\"$(json_escape "${family_label}")\",\"family_description\":\"$(json_escape "${family_desc}")\"}"
        done < <(grep -oiE "(${bad_bot_patterns})" "${access_log}" 2>/dev/null | sort | uniq -c | sort -rn | head -15)

        # Build family summary JSON
        local family_summary="["
        local first_fam=true
        for fam_id in "${!family_totals[@]}"; do
            [[ "${first_fam}" == true ]] && first_fam=false || family_summary+=","
            family_summary+="{\"family\":\"${fam_id}\",\"label\":\"$(json_escape "${family_labels[${fam_id}]}")\",\"total_hits\":${family_totals[${fam_id}]}}"
        done
        family_summary+="]"

        if [[ "${total_bot_ips}" -gt 100 ]]; then
            # Build a readable family breakdown for the issue detail
            local family_detail=""
            for fam_id in "${!family_totals[@]}"; do
                family_detail+="${family_labels[${fam_id}]}: ${family_totals[${fam_id}]} hits. "
            done
            add_issue "HIGH" "Traffic" "Heavy Bot Traffic" "${total_bot_ips} requests from known bad bots. Breakdown — ${family_detail}" "Block via Cloudflare firewall rules, .htaccess, or run: obsidian bots auto-ban"
            print_status "warn" "${total_bot_ips} bad bot requests detected"
            # Print family breakdown
            for fam_id in "${!family_totals[@]}"; do
                echo -e "    ${YELLOW}├─ ${family_labels[${fam_id}]}:${NC} ${family_totals[${fam_id}]} requests"
            done
        elif [[ "${total_bot_ips}" -gt 0 ]]; then
            add_issue "MEDIUM" "Traffic" "Bot Traffic Detected" "${total_bot_ips} requests from known bad bots" "Consider blocking aggressive bots. Run: obsidian bots analyze"
            print_status "warn" "${total_bot_ips} bad bot requests"
        else
            print_status "ok" "No significant bad bot traffic"
        fi

        # DDoS indicator — if single family has extremely high request count
        for fam_id in "${!family_totals[@]}"; do
            if [[ "${family_totals[${fam_id}]}" -gt 5000 ]]; then
                add_issue "CRITICAL" "DDoS" "Potential DDoS / Flood from ${family_labels[${fam_id}]}" "${family_totals[${fam_id}]} requests from ${family_labels[${fam_id}]} bots — possible DDoS or aggressive scraping attack" "Immediate action: block at firewall level. For ${fam_id} bots, consider null-routing at edge (Cloudflare, CSF). Run: obsidian bots auto-ban --family ${fam_id}"
                print_status "crit" "POSSIBLE DDoS: ${family_labels[${fam_id}]} — ${family_totals[${fam_id}]} requests"
            fi
        done

        # Rate abusers
        local top_ip_count
        top_ip_count="$(tail -5000 "${access_log}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')"
        if [[ -n "${top_ip_count}" ]] && [[ "${top_ip_count}" -gt 300 ]]; then
            local top_ip
            top_ip="$(tail -5000 "${access_log}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
            add_issue "HIGH" "Traffic" "Rate Abuse Detected" "IP ${top_ip} made ${top_ip_count} requests recently" "Ban IP: obsidian ban ${top_ip} --reason 'Rate abuse'"
            print_status "warn" "Rate abuser: ${top_ip} (${top_ip_count} requests)"
        fi

        # Scanner detection
        local scanner_count
        scanner_count="$(grep -ciE '(\.env|\.git/|wp-config\.php\.bak|/phpmyadmin|UNION.*SELECT|<script>)' "${access_log}" 2>/dev/null || echo 0)"
        if [[ "${scanner_count}" -gt 10 ]]; then
            add_issue "HIGH" "Traffic" "Vulnerability Scanning Detected" "${scanner_count} scanning attempts in access log" "Review and ban scanner IPs. Run: obsidian bots scanners"
            print_status "warn" "${scanner_count} scanning attempts detected"
        fi
    else
        local family_summary="[]"
        print_status "info" "No access log found — bot analysis skipped"
    fi

    bot_findings+="]"
    json+="\"bots\":{\"total_bad_requests\":${total_bot_ips},\"findings\":${bot_findings},\"family_summary\":${family_summary}},"

    # --- Security Posture ---
    echo -e "\n${BOLD}[5/7] Checking security configuration...${NC}"

    # Firewall
    if [[ "${firewall}" == "none" ]]; then
        add_issue "CRITICAL" "Security" "No Firewall Active" "No firewall (CSF, iptables, nftables) detected" "Install and configure a firewall immediately. For cPanel: install CSF."
        print_status "critical" "No firewall detected!"
    else
        print_status "ok" "Firewall: ${firewall}"
    fi

    # SSH checks
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        local root_login
        root_login="$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
        if [[ "${root_login}" == "yes" ]]; then
            add_issue "HIGH" "Security" "SSH Root Login Enabled" "Direct root SSH login is allowed" "Set PermitRootLogin to 'no' or 'prohibit-password' in /etc/ssh/sshd_config"
            print_status "warn" "SSH root login enabled"
        else
            print_status "ok" "SSH root login disabled"
        fi

        local pwd_auth
        pwd_auth="$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')"
        if [[ "${pwd_auth}" == "yes" ]]; then
            add_issue "MEDIUM" "Security" "SSH Password Auth Enabled" "Password authentication is active, vulnerable to brute force" "Switch to key-based authentication. Set PasswordAuthentication no"
            print_status "warn" "SSH password auth enabled"
        else
            print_status "ok" "SSH password auth disabled"
        fi
    fi

    # World-writable web files
    local www_writable=0
    for wdir in /var/www /home/*/public_html; do
        www_writable=$(( www_writable + $(find ${wdir} -type f -name "*.php" -perm -o+w 2>/dev/null | wc -l || echo 0) ))
    done
    if [[ "${www_writable}" -gt 0 ]]; then
        add_issue "HIGH" "Security" "World-Writable PHP Files" "${www_writable} PHP file(s) are world-writable" "Fix permissions: find /var/www -name '*.php' -perm -o+w -exec chmod o-w {} \\;"
        print_status "warn" "${www_writable} world-writable PHP files"
    else
        print_status "ok" "No world-writable PHP files"
    fi

    # SSL certificate check
    local ssl_issues=0
    for cert in /etc/ssl/certs/*.pem /etc/letsencrypt/live/*/cert.pem; do
        [[ -f "${cert}" ]] || continue
        local expiry
        expiry="$(openssl x509 -enddate -noout -in "${cert}" 2>/dev/null | cut -d= -f2)"
        if [[ -n "${expiry}" ]]; then
            local exp_epoch
            exp_epoch="$(date -d "${expiry}" +%s 2>/dev/null || echo 0)"
            local now_epoch
            now_epoch="$(date +%s)"
            local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
            if [[ "${days_left}" -lt 7 ]]; then
                ssl_issues=$(( ssl_issues + 1 ))
                add_issue "CRITICAL" "Security" "SSL Certificate Expiring" "Certificate expires in ${days_left} days: $(basename "${cert}")" "Renew SSL certificate immediately."
            elif [[ "${days_left}" -lt 30 ]]; then
                add_issue "MEDIUM" "Security" "SSL Certificate Expiring Soon" "Certificate expires in ${days_left} days" "Plan SSL certificate renewal."
            fi
        fi
    done 2>/dev/null

    # Fail2ban
    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            print_status "ok" "Fail2ban active"
        else
            add_issue "MEDIUM" "Security" "Fail2ban Not Running" "Fail2ban is installed but not active" "Start fail2ban: systemctl start fail2ban"
            print_status "warn" "Fail2ban installed but not running"
        fi
    else
        add_issue "LOW" "Security" "No Fail2ban" "Fail2ban is not installed" "Consider installing fail2ban for brute-force protection."
    fi

    # --- Network Connections ---
    echo -e "\n${BOLD}[6/7] Analyzing network connections...${NC}"
    local total_conn
    total_conn="$(ss -s 2>/dev/null | grep 'TCP:' | grep -oP '\d+ estab' | grep -oP '^\d+' || echo 0)"
    local syn_recv
    syn_recv="$(ss -s 2>/dev/null | grep 'synrecv' | grep -oP '\d+' | head -1 || echo 0)"

    if [[ "${syn_recv}" -gt 100 ]]; then
        add_issue "CRITICAL" "Network" "Possible SYN Flood" "${syn_recv} half-open TCP connections detected" "Possible DDoS attack. Enable SYN cookies: sysctl net.ipv4.tcp_syncookies=1"
        print_status "critical" "SYN flood indicator: ${syn_recv} half-open connections"
    fi
    print_status "ok" "TCP connections: ${total_conn} established"

    json+="\"network\":{\"tcp_established\":${total_conn:-0},\"syn_recv\":${syn_recv:-0}},"

    # --- File Integrity (quick check) ---
    echo -e "\n${BOLD}[7/7] Quick file integrity check...${NC}"
    local integrity_issues=0

    # Check critical WordPress files for known tampering
    for critical_file in /var/www/html/wp-config.php /var/www/html/.htaccess /var/www/html/index.php; do
        if [[ -f "${critical_file}" ]]; then
            if grep -qiE '(eval\s*\(|base64_decode|shell_exec|system\s*\(\$)' "${critical_file}" 2>/dev/null; then
                integrity_issues=$(( integrity_issues + 1 ))
                add_issue "CRITICAL" "Integrity" "Critical File Compromised" "Suspicious code in $(basename "${critical_file}")" "Review and restore from clean backup."
                print_status "critical" "Suspicious code in $(basename "${critical_file}")"
            fi
        fi
    done
    [[ "${integrity_issues}" -eq 0 ]] && print_status "ok" "Critical files appear clean"

    # Finalize issues
    health_issues+="]"
    [[ "${health_score}" -lt 0 ]] && health_score=0

    json+="\"score\":${health_score},"
    json+="\"issues\":${health_issues}"
    json+="}"

    # Calculate duration
    local end_time
    end_time="$(date +%s)"
    local duration=$(( end_time - start_time ))

    # Save JSON
    echo "${json}" > "${audit_json}"

    # Summary
    local issue_count
    issue_count="$(echo "${health_issues}" | grep -o '"severity"' | wc -l)"
    local critical_count
    critical_count="$(echo "${health_issues}" | grep -o '"CRITICAL"' | wc -l)"
    local high_count
    high_count="$(echo "${health_issues}" | grep -o '"HIGH"' | wc -l)"

    echo ""
    echo -e "${BOLD}══════════════════════════════════════${NC}"
    echo -e "${BOLD}  Audit Complete${NC}"
    echo -e "${BOLD}══════════════════════════════════════${NC}"

    local grade_color="${GREEN}"
    local grade="A"
    if [[ "${health_score}" -lt 50 ]]; then
        grade="F"; grade_color="${RED}"
    elif [[ "${health_score}" -lt 60 ]]; then
        grade="D"; grade_color="${RED}"
    elif [[ "${health_score}" -lt 70 ]]; then
        grade="C"; grade_color="${YELLOW}"
    elif [[ "${health_score}" -lt 80 ]]; then
        grade="B"; grade_color="${YELLOW}"
    elif [[ "${health_score}" -lt 90 ]]; then
        grade="A-"; grade_color="${GREEN}"
    fi

    echo -e "\n  Security Score: ${grade_color}${BOLD}${health_score}/100 (Grade: ${grade})${NC}"
    echo -e "  Issues Found:  ${issue_count} (${RED}${critical_count} critical${NC}, ${YELLOW}${high_count} high${NC})"
    echo -e "  Duration:      ${duration}s"
    echo -e "  Report saved:  ${audit_json}"

    if [[ -n "${output_file}" ]]; then
        cp "${audit_json}" "${output_file}"
        echo -e "  Copied to:     ${output_file}"
    fi

    echo ""
    echo -e "  Generate PDF:  ${BOLD}obsidian audit report ${audit_id}${NC}"
    echo ""

    return "${critical_count}"
}
