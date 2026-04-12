# Twitter/X Threads for Obsidian Security

---

## Thread 1: The Story

🧵 Last week I found a cryptominer on a client's server that had been running for 3 weeks.

Nobody noticed. Here's how it hid — and how I found it in under 5 minutes:

(thread 👇)

---

1/ The server had 10 WordPress sites on cPanel. Owner said "everything's fine, just a bit slow lately."

That's the #1 red flag in server security. "A bit slow" usually means something is eating your resources.

---

2/ The miner was at:
.config/.cache/fontconfig/lib-update

Notice the path. It's 3 levels deep in dot-directories. `ls` won't show it. Most file managers won't show it. Even some security plugins miss it.

---

3/ How I found it:

find /home -path '*/.*/*' -type f -executable -print0 | xargs -0 file | grep ELF

This finds executable files hidden inside dot-directories. If something in .cache/ is an ELF binary, that's not normal.

---

4/ But the miner was smart. It throttled itself during business hours to avoid detection.

High CPU at 3am? Nobody's checking. Normal CPU at 10am? "Server seems fine."

This is why you need automated scanning, not manual checks.

---

5/ What else we found on the same server:

• PHP 7.4 (EOL since Nov 2022)
• 48K bot requests/day from Bytespider
• SSH root login with password auth
• Disk at 90%
• PHP extMaxIdleTime=10s causing 503 errors

6 issues. All invisible to the owner.

---

6/ I built a tool that checks all of this automatically.

One command. No installs. PDF report with findings + fixes.

Now offering it as a service:
• Quick Scan: €49
• Pro Audit: €149
• Monthly Guard: €99/mo

DM for a free mini-check on your server.

---

## Thread 2: Quick Tips

🧵 5 commands every server admin should run RIGHT NOW:

(your server might be compromised and you don't know it)

---

1/ Find hidden executables:

find /home /tmp /var/tmp -path '*/.*/*' -type f -executable 2>/dev/null

If this returns ANYTHING, investigate immediately. Legitimate software doesn't hide binaries in dot-directories.

---

2/ Check for suspicious cron jobs:

for u in $(cut -f1 -d: /etc/passwd); do
  echo "=== $u ===";
  crontab -u $u -l 2>/dev/null;
done

Look for: curl|bash, wget|sh, base64, /tmp paths, or URLs you don't recognize.

---

3/ See who's hammering your server:

tail -10000 /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

If one IP has thousands of hits and it's not Google/Bing, it's likely a bot burning your resources.

---

4/ Check your SSH config:

grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config

If both say "yes" — you're one brute-force attack away from a breach. Fix this today.

---

5/ Check your PHP version:

php -v | head -1

PHP 7.x or 8.0? Those are END OF LIFE. Known vulnerabilities. No patches coming.

Upgrade to 8.2+ or you're running with unlocked doors.

---

6/ Want all of this automated + 20 more checks?

I built Obsidian — a security audit tool for cPanel servers.

One command, professional PDF report, zero installs.

DM for a free check ⚡

---

## Thread 3: Monthly Guard Launch

Launching today: Monthly Guard by Obsidian Security 🛡️

For €99/month, your server gets:

✓ Weekly security scans
✓ Real-time file monitoring
✓ Bot traffic auto-blocking
✓ Monthly PDF report
✓ Priority incident response (< 4h)
✓ No contracts, cancel anytime

If you manage WordPress/WooCommerce on cPanel, this is for you.

First 5 clients get the first month free.

DM me or reply with "guard" 👇
