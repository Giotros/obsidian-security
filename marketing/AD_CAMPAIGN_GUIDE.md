# Obsidian Security — Ad Campaign & Promotion Guide

Complete step-by-step guide to promoting Obsidian Security on YouTube, Google Ads, and Meta (Facebook/Instagram). Written for someone starting from zero — no existing ad accounts.

---

## 1. RECORDING THE VIDEO AD

The promo video is an HTML animation at `marketing/video/obsidian-ad.html`. You need to screen-record it into MP4 files.

### Install OBS Studio (Free)

1. Download from https://obsproject.com
2. Install and open OBS Studio

### Recording Settings

Go to **Settings → Output → Recording**:

| Setting | Value |
|---------|-------|
| Format | MP4 |
| Encoder | x264 (or NVENC if you have NVIDIA) |
| Rate Control | CRF |
| CRF Value | 18 (high quality) |
| Keyframe Interval | 2 |

Go to **Settings → Video**:

| Resolution | Use Case |
|-----------|----------|
| 1920 × 1080 | YouTube, Google Ads (16:9) |
| 1080 × 1080 | Meta Feed (1:1) — resize browser window |
| 1080 × 1920 | Meta Stories/Reels (9:16) — resize browser window |

### Three Versions to Record

You need **three cuts** of the video for different ad placements:

| Cut | Duration | Scenes | Use |
|-----|----------|--------|-----|
| **15-second** | ~15s | Hook → Breach Stats → Logo Reveal (scenes 1-3) | YouTube non-skippable pre-roll, Meta Stories |
| **30-second** | ~31s | Hook → Score Reveal (scenes 1-5) | YouTube skippable pre-roll, Meta Feed |
| **Full** | ~58s | All 9 scenes | YouTube organic, website, LinkedIn |

### How to Record Each Cut

1. Open `obsidian-ad.html` in Chrome (press F11 for fullscreen)
2. Click anywhere to start the ambient audio
3. In OBS: add a "Window Capture" source → select Chrome
4. For the **15s cut**: let it play through scenes 1-3, then stop recording when the logo scene ends
5. For the **30s cut**: let it play through scenes 1-5 (score reveal), then stop
6. For the **full version**: let it play to the end

### Audio Options

The HTML file has a built-in ambient soundtrack (Web Audio API). For a more polished result:

**Option A — Use the built-in audio:** Click anywhere on the page to activate it. OBS will capture desktop audio automatically.

**Option B — Add professional background music:** Record the video without audio, then add music in a free editor like:
- **DaVinci Resolve** (free, professional) — https://www.blackmagicdesign.com/products/davinciresolve
- **CapCut** (free, simpler) — https://www.capcut.com

Recommended royalty-free music sources:
- **Artlist.io** (~€10/month, great cinematic tracks)
- **Epidemic Sound** (~€13/month)
- **YouTube Audio Library** (free, in YouTube Studio)

Search for: "dark ambient technology" or "cinematic cybersecurity" or "dark corporate"

---

## 2. YOUTUBE CHANNEL SETUP

Before running ads, you need a YouTube channel.

### Step by Step

1. Go to https://youtube.com and sign in with your Google account
2. Click your profile icon → **Create a channel**
3. Name it **"Obsidian Security"**
4. Upload a profile picture (use the obsidian diamond logo — screenshot from the video's logo reveal scene)
5. Add a banner image (1546 × 423 px) — dark theme with "OBSIDIAN SECURITY" text

### Upload the Full Video

1. Click **Create → Upload video**
2. Upload the **full 58-second version**
3. Title: `Server Security Audit in 60 Seconds | Obsidian Security`
4. Description:
```
Your server could be compromised right now. Obsidian Security identifies threats in minutes — cryptominers, bot attacks, misconfigurations, and vulnerabilities.

→ Pure Bash. Zero dependencies. One command.
→ 7-phase security audit
→ Professional PDF report
→ Real-time alerts via Telegram

Services:
• Quick Scan — €49 (one-time)
• Pro Audit — €149 (expert review)
• Monthly Guard — €99/month (continuous protection)

Contact: giorgostrox@gmail.com

#serversecurity #cybersecurity #wordpress #cpanel #securityaudit
```
5. Tags: server security, security audit, cybersecurity, wordpress security, cpanel security, malware detection, bot protection, server monitoring
6. Set as **Channel Trailer** (Settings → Customize channel → For new visitors)

---

## 3. GOOGLE ADS SETUP

### Create Your Account

1. Go to https://ads.google.com
2. Click **Start Now**
3. Sign in with the same Google account as your YouTube channel
4. Skip the "Smart Campaign" wizard — click **Switch to Expert Mode** at the bottom
5. Enter billing info (credit/debit card)

### Campaign 1: YouTube Video Ads

1. Click **+ New Campaign**
2. Objective: **Leads** (or "Create a campaign without a goal's guidance" for more control)
3. Campaign type: **Video**
4. Campaign subtype: **Video reach campaign**

#### Ad Groups & Targeting

| Setting | Value |
|---------|-------|
| **Locations** | Greece, United Kingdom, Germany, Netherlands, United States |
| **Languages** | English |
| **Budget** | €10/day to start |
| **Bidding** | Target CPV (Cost Per View) — start at €0.05–0.10 |

**Audience Targeting (critical):**

In-Market Audiences:
- Web Hosting & Domain Services
- Business Technology Solutions
- IT Security Software

Affinity Audiences:
- Technology Professionals
- Business Professionals

Custom Audiences (create your own):
- Keywords people have searched: `server security`, `wordpress hacked`, `malware on server`, `cpanel security`, `website security audit`, `server monitoring`, `ddos protection`, `website hacked what to do`
- Websites visited: `wordfence.com`, `sucuri.net`, `siteground.com`, `cloudways.com`, `hostgator.com`

**Demographic Targeting:**
- Age: 25-54
- Gender: All

#### Ad Formats

Create **three ad variations**:

| Format | Video | When It Shows |
|--------|-------|---------------|
| **Non-skippable in-stream** | 15s cut | Before videos (forced view) |
| **Skippable in-stream** | 30s or full | Before/during videos (skip after 5s) |
| **In-feed** | Full | YouTube search results, home feed |

For each ad, set:
- **Final URL**: Your landing page (see Section 6)
- **Display URL**: obsidian.security
- **Call-to-action**: "Learn More" or "Get Quote"
- **Headline**: "Server Security Audit — From €49"

### Campaign 2: Google Search Ads

Catches people actively searching for solutions — highest conversion intent.

1. **+ New Campaign** → Leads → Search
2. Budget: €10/day

**Keywords to bid on (exact match):**

```
[server security audit]
[website security scan]
[wordpress security audit]
[cpanel security check]
[malware removal server]
[server malware scan]
[website hacked help]
[server monitoring service]
```

**Broad match (for discovery):**

```
server security service
wordpress security expert
website security consultation
managed server security
```

**Negative keywords (add to avoid wasted spend):**

```
free
download
tutorial
how to
course
certification
job
salary
```

**Ad Copy Examples:**

Ad 1:
```
Headline 1: Server Security Audit | From €49
Headline 2: 7-Phase Scan — PDF Report in 24h
Headline 3: Cryptominers • Bots • Vulnerabilities
Description: Professional server security audit. Identify threats before they escalate. Real findings, actionable remediation. Contact us today.
```

Ad 2:
```
Headline 1: Is Your Server Compromised?
Headline 2: Find Out in 5 Minutes | Obsidian Security
Headline 3: Trusted by Server Administrators
Description: Our audit found a hidden cryptominer running for 21 days undetected. Don't wait for your clients to notice. Get your server scanned.
```

---

## 4. META ADS SETUP (Facebook & Instagram)

### Create Your Business Account

1. Go to https://business.facebook.com
2. Click **Create Account**
3. Business name: **Obsidian Security**
4. Enter your details
5. Go to **Business Settings → Ad Accounts → Add → Create a new ad account**

### Create a Facebook Page

1. From Business Suite → **Create Page**
2. Page name: **Obsidian Security**
3. Category: **Information Technology Company**
4. Add profile pic and cover photo (same branding as YouTube)
5. Create an Instagram business account linked to this page

### Install Meta Pixel

Critical for tracking conversions:

1. Go to **Events Manager** in Business Suite
2. Click **Connect Data Sources → Web → Meta Pixel**
3. Name it "Obsidian Security Pixel"
4. Add the pixel code to your landing page's `<head>` section
5. Set up a **Lead** event for when someone submits the contact form

### Create Your Campaign

1. Go to **Ads Manager** → **+ Create**
2. Objective: **Leads** (or **Traffic** if you don't have a form yet)
3. Budget: €10/day
4. Schedule: Run continuously

**Ad Set — Targeting:**

| Setting | Value |
|---------|-------|
| **Locations** | Greece, UK, Germany, Netherlands, US |
| **Age** | 25-54 |
| **Interests** | Web development, WordPress, Server (computing), cPanel, System administration, Cybersecurity, Linux, Web hosting, Cloud computing, DevOps |
| **Behaviors** | Small business owners, IT decision makers |

**Ad Creatives — 3 Variations:**

| Placement | Format | Video |
|-----------|--------|-------|
| Feed (FB + IG) | 1:1 square | 30s cut (re-recorded at 1080×1080) |
| Stories + Reels | 9:16 vertical | 15s cut (re-recorded at 1080×1920) |
| In-Stream | 16:9 | 30s cut |

**Ad Copy for Feed:**

```
Your server could be compromised right now.

During a routine audit, we found:
→ A hidden cryptominer (running 21 days undetected)
→ 48,000 bot requests per day
→ SSH root login with password auth enabled

All on a single production server.

Obsidian Security identifies threats in minutes.
Starting at €49.

→ giorgostrox@gmail.com
```

**Stories/Reels Caption:**
```
Is your server secure?
Most admins never find out.
→ Obsidian Security | From €49
```

---

## 5. BUDGET BREAKDOWN

### Recommended Starting Budget: €400–540/month

| Platform | Daily | Monthly | Purpose |
|----------|-------|---------|---------|
| Google Search Ads | €8 | €240 | Highest intent — people searching for solutions |
| YouTube Video Ads | €5 | €150 | Brand awareness + reach |
| Meta Ads | €5 | €150 | Reach IT professionals on social |
| **Total** | **€18** | **~€540** | |

### Tight Budget: €300/month

| Platform | Daily | Monthly | Priority |
|----------|-------|---------|----------|
| Google Search Ads | €7 | €210 | #1 — Highest conversion intent |
| Meta Ads | €3 | €90 | #2 — Good targeting for IT pros |
| **Total** | **€10** | **€300** | |

Add YouTube video ads once you have steady leads from search.

### Expected Performance (B2B Cybersecurity Benchmarks)

| Metric | Google Search | YouTube | Meta |
|--------|---------------|---------|------|
| CTR | 3–6% | 0.5–1.5% | 0.8–2% |
| Cost per Click | €0.80–2.50 | €0.03–0.10 (CPV) | €0.50–1.50 |
| Conversion Rate | 3–8% | 0.5–2% | 1–3% |
| Cost per Lead | €10–40 | €15–50 | €10–35 |

At €400/month expect roughly **15–40 leads per month** depending on targeting quality.

---

## 6. LANDING PAGE

You need a page where ad traffic lands.

### Option A: Carrd (Recommended — €19/year)
- https://carrd.co — simple one-page site builder
- Connect a custom domain if you have one

### Option B: Google Sites (Free)
- https://sites.google.com — basic but functional

### What the Landing Page Needs

1. **Hero**: "Server Security Audit" + video embed + "Get Your Audit — From €49" button
2. **Problem**: "48,000 bot requests. Hidden cryptominers. Unpatched CVEs. All found on a single production server."
3. **Solution**: The 7-phase audit, PDF report, remediation guidance
4. **Pricing cards**: Quick Scan (€49), Pro Audit (€149), Monthly Guard (€99/mo)
5. **Contact form**: Name, Email, Server count, Message → sends to giorgostrox@gmail.com
6. **Trust signals**: "Pure Bash — zero dependencies", "No permanent installation", "Your IP always whitelisted"

---

## 7. CONVERSION TRACKING

### Google Ads

1. In Google Ads → **Tools → Conversions**
2. **+ New conversion action → Website**
3. Set up "Lead" conversion for contact form submissions
4. Add the conversion tag to your landing page

### Meta Pixel

Already created in Section 4. Fire a `Lead` event when the form is submitted. Meta will optimize to find more people like your converters.

### UTM Parameters

Add to ALL your ad URLs for tracking:

```
?utm_source=google&utm_medium=search&utm_campaign=obsidian-audit
?utm_source=google&utm_medium=youtube&utm_campaign=obsidian-video
?utm_source=meta&utm_medium=social&utm_campaign=obsidian-feed
```

---

## 8. ADVANCED STRATEGIES (After Week 2)

### Retargeting

After your pixel/tags collect ~100 visitors:

**Google:** Remarketing audience → show YouTube ads to people who visited your page but didn't convert.

**Meta:** Custom Audience → "Website visitors last 30 days" → show a different ad (case study or testimonial).

### Lookalike Audiences (Meta)

Once you have 30+ leads:
1. Audiences → Create → Lookalike Audience
2. Source: your lead list or pixel data
3. Size: 1% (most similar to your actual leads)

### A/B Testing

Run 2–3 ad variations simultaneously:
- Different headlines
- Different video cuts (15s vs 30s)
- Different CTAs ("Get Your Audit" vs "Check Your Server" vs "From €49")

Kill underperformers after 5–7 days. Scale winners.

### LinkedIn Ads (Optional — Higher Budget)

If budget allows (€15–25/day minimum):
- Target: IT Managers, System Administrators, CTOs, DevOps Engineers
- LinkedIn CPCs are €3–8 but lead quality is excellent for B2B

---

## 9. LAUNCH CHECKLIST

- [ ] Record 15s, 30s, and full video at 1920×1080 (16:9)
- [ ] Record 30s version at 1080×1080 (square for Meta feed)
- [ ] Record 15s version at 1080×1920 (vertical for Meta Stories)
- [ ] Create YouTube channel "Obsidian Security"
- [ ] Upload full video to YouTube
- [ ] Create landing page with contact form
- [ ] Set up Google Ads account
- [ ] Create Google Search campaign
- [ ] Create YouTube Video campaign
- [ ] Set up Meta Business Suite
- [ ] Create Facebook Page "Obsidian Security"
- [ ] Install Meta Pixel on landing page
- [ ] Create Meta campaigns (Feed + Stories)
- [ ] Set up conversion tracking on both platforms
- [ ] Set daily budgets (€10–18/day total)
- [ ] Launch and monitor 7 days before making changes

---

## 10. WEEK-BY-WEEK PLAN

**Week 1:** Set up all accounts. Record videos. Create landing page. Launch Google Search ads only.

**Week 2:** Launch YouTube and Meta campaigns. Monitor search ad performance. Pause keywords with high cost and no conversions.

**Week 3:** Review all metrics. Kill underperforming ads. Scale winners. Set up retargeting.

**Week 4:** A/B test new creatives. Create lookalike audience on Meta. Consider LinkedIn if budget allows.

**Monthly:** Review cost per lead across platforms. Shift budget to best performer. Refresh creatives every 4–6 weeks to prevent ad fatigue.
