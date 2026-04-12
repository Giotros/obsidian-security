# How We Found a Hidden Cryptominer That Ran Undetected for 3 Weeks

*By George — Obsidian Security*

A hosting client reached out last month with a familiar complaint: "The server feels sluggish, sites are throwing 503 errors, and my clients are complaining."

They'd already restarted Apache, bumped up PHP memory limits, and cleared WordPress caches. Nothing helped. So we ran a Obsidian security audit.

What we found in the first 5 minutes told a different story.

## The Setup

The server was a pretty standard cPanel/WHM box — 10 WordPress and WooCommerce sites, shared hosting environment, nothing exotic. It had been running without issues for over a year. The problems started gradually, which is exactly why nobody raised an alarm.

## What We Found

### 1. A Cryptominer Hiding in Plain Sight

The binary was at `.config/.cache/fontconfig/lib-update` inside one of the user home directories. Three levels deep inside dot-directories — invisible to `ls`, invisible to most file managers, invisible to most security plugins.

The name `lib-update` was deliberately chosen to look like a system process. Running `file` on it confirmed it was an ELF executable — a compiled binary that had no business being in a user's `.cache` directory.

The clever part: it throttled its CPU usage during business hours. At 3am it would spike to 80-90% CPU. By 9am it dropped to 15-20%. Just enough to cause "sluggishness" without triggering obvious alerts.

### 2. PHP 7.4 — Dead Since November 2022

The server was still running PHP 7.4 across all sites. PHP 7.4 reached end-of-life in November 2022, meaning no security patches for over a year at the time of our audit. Multiple known CVEs, any of which could have been the initial entry point for the cryptominer.

### 3. 48,000 Bot Requests Per Day

Bytespider (ByteDance's crawler) alone was responsible for roughly 30,000 requests per day. AhrefsBot, SemrushBot, and a handful of others made up the rest. None of these bots were generating revenue. All of them were consuming CPU, memory, and bandwidth.

### 4. PHP extMaxIdleTime Set to 10 Seconds

This one was causing the 503 errors directly. The PHP-FPM idle timeout was set so low that worker processes were being killed before they could finish handling requests during traffic spikes. Combined with the cryptominer eating CPU, it created a perfect storm — PHP workers would start, get starved of CPU time, time out, and the user would see a 503.

### 5. SSH Root Login with Password Auth

The SSH configuration still had `PermitRootLogin yes` and `PasswordAuthentication yes`. This is the equivalent of leaving your front door unlocked with a sign that says "please don't come in." Brute-force SSH attacks are constant on any public server.

### 6. Disk at 90% Capacity

Log files, old backups, and the cryptominer's own output had pushed the disk to 90%. Once a disk crosses ~95%, bad things start happening — databases can't write temporary tables, PHP can't create session files, and email queues grind to a halt.

## How We Detected It

Our audit tool runs a series of automated checks. For the cryptominer specifically, three checks converged:

**Hidden executable scan** — We search for executable files inside dot-directories under /home, /tmp, /var/tmp, and /dev/shm. Legitimate software almost never places compiled binaries inside hidden directories. This is a nearly zero-false-positive detection method.

**Process analysis** — We scan running processes for patterns associated with miners: processes running from /tmp or dot-directories, processes with deleted binary references in /proc/PID/exe, and processes with suspiciously high CPU usage over sustained periods.

**Cron job audit** — The miner had a persistence mechanism: a cron job that checked every 5 minutes if the process was still running, and restarted it if not. The cron entry contained a `curl | bash` pattern, which is one of our signature red flags.

## The Fix

Remediation took about 30 minutes:

The cryptominer process was killed, the binary removed, and the malicious cron job deleted. We then upgraded PHP from 7.4 to 8.2, which also closed the likely entry vector. The PHP-FPM configuration was adjusted with a proper `extMaxIdleTime` of 300 seconds. SSH was hardened — root login disabled, password authentication replaced with key-based auth. Bot blocking rules were added for Bytespider and non-essential crawlers. Old log files and backups were cleaned up, bringing disk usage down to 62%.

## The Aftermath

Within an hour of cleanup, the client reported sites were "noticeably faster." CPU usage dropped from a constant 70-80% to a comfortable 25-30%. The 503 errors stopped completely.

The client is now on our Monthly Guard plan, which runs weekly scans and monitors for file changes in real time. Two months in — no re-infections, no incidents.

## The Lesson

This wasn't a sophisticated attack. The cryptominer used well-known techniques: dot-directory hiding, cron persistence, CPU throttling. But it worked for 3 weeks on a server managed by someone who knows what they're doing.

The problem isn't knowledge — it's attention. Server admins are busy. They're managing dozens of sites, handling client requests, dealing with updates. Security checks fall to the bottom of the list until something breaks.

That's exactly why automated, regular security audits exist. Not because admins can't do these checks manually, but because they shouldn't have to remember to.

---

*Want to know what's running on your servers? Obsidian Security offers automated security audits for cPanel/WHM environments. One command, no installs, professional PDF report.*

*Get a free mini-check: contact@obsidian.security*
