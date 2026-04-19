FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    curl \
    procps \
    inotify-tools \
    apache2 \
    php \
    php-cli \
    net-tools \
    iproute2 \
    iptables \
    openssl \
    bc \
    file \
    xxd \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod cgid headers rewrite

# Create fake WordPress structure
RUN mkdir -p /var/www/html/wp-content/plugins/akismet \
    /var/www/html/wp-content/themes/flavor \
    /var/www/html/wp-admin \
    /var/www/html/wp-includes \
    && echo '<?php // WordPress config' > /var/www/html/wp-config.php \
    && echo '<?php // Settings' > /var/www/html/wp-settings.php \
    && echo '<?php // Login' > /var/www/html/wp-login.php \
    && echo '<?php // Index' > /var/www/html/index.php \
    && echo '<?php // xmlrpc' > /var/www/html/xmlrpc.php \
    && echo '<?php // Akismet' > /var/www/html/wp-content/plugins/akismet/akismet.php \
    && echo '<?php // Theme functions' > /var/www/html/wp-content/themes/flavor/functions.php \
    && echo 'RewriteEngine On' > /var/www/html/.htaccess

# Create home directories for malware simulation
RUN mkdir -p /home/mybagonline/.config/.cache/fontconfig \
    /home/testuser/public_html

# Copy Obsidian source
COPY . /opt/obsidian-src/

# Install Obsidian manually (non-interactive)
RUN mkdir -p /opt/obsidian/{lib,agent,server,rules,presets,data,logs} /var/run/obsidian \
    && cp /opt/obsidian-src/lib/*.sh /opt/obsidian/lib/ \
    && cp /opt/obsidian-src/obsidian /opt/obsidian/obsidian \
    && cp /opt/obsidian-src/agent/obsidian-agent.sh /opt/obsidian/agent/ \
    && cp /opt/obsidian-src/server/obsidian-api.sh /opt/obsidian/server/ \
    && cp /opt/obsidian-src/rules/* /opt/obsidian/rules/ 2>/dev/null || true \
    && cp /opt/obsidian-src/presets/* /opt/obsidian/presets/ 2>/dev/null || true \
    && chmod +x /opt/obsidian/obsidian /opt/obsidian/agent/*.sh /opt/obsidian/server/*.sh \
    && ln -sf /opt/obsidian/obsidian /usr/local/bin/obsidian

# Create minimal config
RUN printf '%s\n' \
    "hostname = obsidian-test" \
    "log_level = INFO" \
    "firewall = iptables" \
    "allow_ban_private = true" \
    "auto_ban_critical = false" \
    "monitor_path = /var/www/html" \
    "alert_min_severity = LOW" \
    "rate_window = 60" \
    "rate_max_requests = 120" \
    "rate_ban_threshold = 300" \
    "cpu_warn_threshold = 80" \
    "cpu_crit_threshold = 95" \
    "mem_warn_threshold = 80" \
    "mem_crit_threshold = 95" \
    "disk_warn_threshold = 80" \
    "disk_crit_threshold = 90" \
    "php_min_idle_time = 30" \
    > /opt/obsidian/obsidian.conf

COPY test-environment/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/obsidian

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
