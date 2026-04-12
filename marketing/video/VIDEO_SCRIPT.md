# Obsidian Security — Video Demo Script

## Overview
- **Duration:** ~2:30 minutes
- **Style:** Dark terminal aesthetic + clean narration overlays + dramatic reveals
- **Music:** Dark ambient / tech soundtrack (suggestions: Epidemic Sound "Dark Tech" category)
- **Voice:** Professional, confident, slightly urgent tone

---

## SCENE 1: THE HOOK (0:00 – 0:15)

### Visual
Black screen → slow fade in of text

### Narration (Voiceover)
> "Your server is running right now. But do you really know what's running ON it?"

### Text on Screen
```
Your server is running right now.
But do you really know what's running ON it?
```

### Sound
Deep bass hit on "ON it"

---

## SCENE 2: THE PROBLEM (0:15 – 0:35)

### Visual
Quick cuts of real stats appearing one by one, red accent color:

### Narration
> "Last week we audited a cPanel server with 10 WordPress sites. The owner said everything was fine. Here's what we found."

### Text Overlays (appear one by one with sound effects)
```
🔴 Cryptominer running for 3 weeks — hidden in .config/.cache/
🔴 PHP 7.4 — end of life, known vulnerabilities unpatched
🔴 48,000 bot requests per day — burning CPU and bandwidth
🔴 SSH root login with password authentication — wide open
🔴 Disk at 90% — approaching critical failure
```

### Sound
Each item: short alert/ping sound

---

## SCENE 3: ENTER OBSIDIAN (0:35 – 0:50)

### Visual
Terminal fades in. Obsidian banner appears.

### Narration
> "Meet Obsidian. One command. Zero installs. Complete security audit."

### Terminal Action
```bash
$ curl -sL https://obsidian.security/audit.sh | sudo bash
```

Obsidian ASCII banner appears:
```
╔══════════════════════════════════════╗
║    OBSIDIAN SECURITY SUITE v1.0      ║
║    Server Security Audit Tool       ║
╚══════════════════════════════════════╝
```

---

## SCENE 4: THE SCAN (0:50 – 1:30)

### Visual
Terminal running the full audit — each phase appears with results

### Narration
> "Obsidian scans seven critical areas of your server. System health. Malware. Hidden executables. Cron jobs. Bot traffic. SSH configuration. File integrity. All in under 60 seconds."

### Terminal Action (animated typing, each section appears)
```
[1/7] Collecting system information...
  ✓ Ubuntu 22.04.3 LTS | 8 cores | 16GB RAM
  ⚠ CPU Usage: 78% — ELEVATED

[2/7] Scanning for malware...
  ✗ CRITICAL: Hidden binary at .config/.cache/fontconfig/lib-update
  ✗ CRITICAL: Suspicious cron: curl -sL | bash (every 5 minutes)
  ✗ CRITICAL: Process mining crypto since 2026-03-18

[3/7] Health check...
  ⚠ PHP 7.4.33 — END OF LIFE (Nov 2022)
  ⚠ Disk usage: 90%
  ⚠ extMaxIdleTime=10s — causing 503 errors

[4/7] Analyzing bot traffic...
  ┌─────────────────────────────────────────┐
  │ Bot Family Breakdown                    │
  ├──────────────────────┬──────┬───────────┤
  │ AI Training Crawler  │ 30K  │ HIGH      │
  │ SEO Crawler          │ 13K  │ MEDIUM    │
  │ Vuln Scanner         │ 3.7K │ HIGH      │
  │ Scraper / Generic    │ 1.3K │ MEDIUM    │
  └──────────────────────┴──────┴───────────┘
  ✗ CRITICAL: Potential DDoS from AI Training Crawler (Bytespider)

[5/7] Checking security configuration...
  ✗ SSH: PermitRootLogin = yes
  ✗ SSH: PasswordAuthentication = yes
  ⚠ fail2ban not installed

[6/7] Analyzing network connections...
  ✓ No SYN flood detected
  ⚠ Top IP: 203.0.113.45 (89 connections)

[7/7] File integrity quick check...
  ✓ No unexpected changes detected
```

### Sound
- Phase transitions: subtle whoosh
- Critical findings: alert tone
- Check marks: soft click

---

## SCENE 5: THE SCORE (1:30 – 1:45)

### Visual
Terminal shows final score → transitions to the PDF report cover page

### Narration
> "Every scan produces a security score and a professional PDF report. Your client sees exactly what's wrong, why it matters, and how to fix it."

### Terminal Action
```
══════════════════════════════════════
  SECURITY SCORE: 42/100  [Grade: F]
══════════════════════════════════════

  CRITICAL: 3 issues — fix within hours
  HIGH:     4 issues — fix within 48h
  MEDIUM:   3 issues — fix within 1 week
  LOW:      1 issue  — fix when convenient

  Report saved: audit_20260406_143000.json
  Generating PDF report...
  ✓ Report ready: obsidian-audit-report.pdf
```

### Visual Transition
Terminal slides left → PDF report cover page slides in from right
Show pages flipping through: Executive Summary → Findings → Bot Family Breakdown → Action Plan

---

## SCENE 6: BOT FAMILY INTELLIGENCE (1:45 – 2:00)

### Visual
Zoom into the Bot Traffic Analysis page of the PDF

### Narration
> "Obsidian doesn't just count bots. It classifies them by family — AI crawlers, SEO tools, vulnerability scanners, scrapers. Your client understands exactly who's attacking their server and why."

### Visual
Highlight the Bot Family Breakdown table with a subtle glow effect
Show the family descriptions scrolling

---

## SCENE 7: THE OFFER (2:00 – 2:20)

### Visual
Clean slide with pricing — dark background, accent colors

### Narration
> "Three simple options. Quick Scan for 49 euros — automated report in 24 hours. Pro Audit for 149 — deep manual review with remediation guidance. Or Monthly Guard for 99 per month — continuous monitoring, weekly scans, and priority response."

### Text on Screen
```
QUICK SCAN     €49      Automated scan, PDF report, 24h
PRO AUDIT      €149     Deep review + remediation guidance, 48h
MONTHLY GUARD  €99/mo   Continuous monitoring + monthly reports
```

---

## SCENE 8: CTA (2:20 – 2:30)

### Visual
Obsidian logo + tagline + contact

### Narration
> "Your server has security holes. Let's find them before someone else does."

### Text on Screen
```
OBSIDIAN SECURITY

Your server has security holes.
Let's find them.

contact@obsidian.security
```

### Sound
Final bass hit → fade to black

---

## PRODUCTION NOTES

### Screen Recording Setup
1. Use the animated HTML demo (demo.html) as the visual source
2. Record with OBS at 1920x1080, 60fps
3. The HTML demo auto-plays all scenes with proper timing
4. Record voiceover separately, sync in post

### Voiceover Tips
- Keep it calm but authoritative
- Slight pause before each "critical" finding reveal
- Speed up slightly during the scan phase to create momentum
- Slow down for the pricing/CTA section

### Color Palette
- Background: #0a0f1a (dark navy)
- Accent: #00d4aa (teal green)
- Critical: #ef4444 (red)
- Warning: #f59e0b (amber)
- Text: #e2e8f0 (light gray)

### Music Recommendations (Royalty-Free)
- Epidemic Sound: "Digital Tension" or "Cyber Dark"
- Artlist: Search "dark technology" or "cybersecurity"
- YouTube Audio Library: "Lurking" or "Restricted"

### Alternative: AI Voiceover
If you don't want to record yourself:
- ElevenLabs (elevenlabs.io) — best quality, ~$5
- Use "Adam" or "Antoni" voice for professional tech feel
