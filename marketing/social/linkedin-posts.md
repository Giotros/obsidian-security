# LinkedIn Posts for Obsidian Security

Use these as-is or adapt. Best posting times: Tuesday-Thursday, 8-10am local.

---

## Post 1: The Hook (Storytelling)

Last week I ran a security audit on a client's cPanel server.

10 WordPress sites. "Everything's fine," they said.

In under 5 minutes, I found:

→ A cryptominer hiding in .config/.cache/fontconfig/lib-update
→ PHP 7.4 — end of life since November 2022
→ 48,000 bot requests per day from Bytespider alone
→ SSH root login with password authentication enabled
→ Disk at 90% capacity

The cryptominer had been running for 3 weeks.
Nobody noticed because it was smart — it throttled itself during business hours.

The client was paying for hosting performance they never got.

Here's the thing: this isn't unusual. 7 out of 10 servers I audit have at least one critical issue the owner doesn't know about.

If you manage servers (or your agency does), when was the last time you actually checked what's running on them?

I'm now offering security audits as a service. One command, no installs, professional PDF report with findings and fixes.

Drop me a message if you want a free mini-check on your server.

#ServerSecurity #cPanel #WHM #WordPress #CyberSecurity #Sysadmin

---

## Post 2: Educational (Value-first)

5 things I check on every cPanel server audit (and you should too):

𝟭. Hidden executables in dot-directories
  Malware loves to hide in .config/, .cache/, .local/ inside /home.
  Run: find /home -path '*/.*/*' -type f -executable
  If you see ELF binaries there, you have a problem.

𝟮. PHP version
  PHP 7.4 reached EOL in Nov 2022. PHP 8.0 in Nov 2023.
  If you're running either, you have unpatched CVEs.
  Check: php -v

𝟯. Cron jobs
  Attackers persist through cron. Check ALL user crontabs:
  for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
  Look for curl|bash, base64, or anything hitting /tmp.

𝟰. SSH configuration
  PermitRootLogin yes + PasswordAuthentication yes = open invitation.
  Check: grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config

𝟱. Bot traffic
  tail -5000 /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
  If one IP has 10x more requests than your users, it's a bot.

Want a proper audit? I built a tool that checks all of this (and 20+ more things) automatically.

Free mini-check for anyone who comments "audit" below.

#Linux #ServerSecurity #DevOps #WordPress #cPanel #InfoSec

---

## Post 3: The Offer (Direct)

I'm launching a security audit service for web hosting and agencies.

Who it's for:
→ You manage cPanel/WHM servers
→ You host WordPress or WooCommerce sites
→ You've never had a formal security audit
→ You suspect "something's off" but don't know where to look

What you get:
→ Professional PDF report with a security score (0-100)
→ Every finding categorized by severity (Critical/High/Medium)
→ Step-by-step remediation instructions
→ No software to install permanently

How it works:
1. You run one command on your server
2. It scans for malware, bots, misconfigs, outdated software
3. I generate a professional report and walk you through it

Pricing:
Quick Scan: €49 (automated, 24h turnaround)
Pro Audit: €149 (manual review + guidance)
Monthly Guard: €99/mo (continuous monitoring)

DM me or comment below for a free mini-check.

#CyberSecurity #WebHosting #cPanel #WordPress #SecurityAudit

---

## Post 4: Case Study (After first few clients)

[Use this template after completing 2-3 audits]

Case study: How we found a hidden cryptominer that was costing a hosting company €{{AMOUNT}}/month in wasted resources.

The problem:
→ Server hosting {{N}} WordPress sites
→ CPU usage consistently at {{X}}% even during off-hours
→ Sites loading slowly, clients complaining
→ No explanation from monitoring tools

What our audit found:
→ Cryptominer binary hidden in {{PATH}}
→ Persistence mechanism via {{METHOD}}
→ Running since {{DATE}} ({{WEEKS}} weeks undetected)
→ Estimated resource cost: €{{AMOUNT}}/month

How we fixed it:
→ Identified the entry point ({{ENTRY}})
→ Removed the malware and persistence mechanisms
→ Hardened the server configuration
→ Set up monitoring to prevent re-infection

Result:
→ CPU dropped from {{X}}% to {{Y}}%
→ Site load times improved by {{Z}}%
→ Client now on Monthly Guard — no re-infections in {{MONTHS}} months

Want to know what's hiding on your servers? Link in comments.

#CaseStudy #CyberSecurity #Malware #WebHosting #ServerAdmin
