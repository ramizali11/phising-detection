# PhishGuard 🛡

**Heuristic Phishing URL Risk Analyzer**  
GTU Cybersecurity Bootcamp Project

---

## Overview

PhishGuard is a lightweight, client-side web application that analyzes URL strings for
heuristic indicators of phishing. It runs entirely in the browser — no server, no database,
no backend, and no external APIs. Users paste a URL, click **Analyze**, and receive:

- A **prominent color-coded warning panel** with an icon, risk label, and specific recommendation
- A **numeric risk score** (0–100) with a visual bar and level badge
- A **list of detected warning signs**, each labeled with its rule ID, severity, point value,
  and a plain-English explanation of why it matters
- A **score breakdown** showing base points and any combination bonuses applied
- **Recommended precautions** tailored to the specific findings
- **Scan history** stored in `localStorage` (persists across browser sessions)

> ⚠ **Results are heuristic estimates, not verdicts.**  
> A high score means the URL shares structural traits with known phishing patterns.  
> A low score does not guarantee the URL is safe.

---

## Features

| Feature | Detail |
|---------|--------|
| 13 detection rules | IP host, punycode IDN, URL shortener, excessive length, suspicious keywords, excessive subdomains, brand impersonation in subdomain, phishing keywords in subdomain, hyphen in domain, plain HTTP, non-standard port, misleading `@` symbol, double-slash redirect |
| Severity-weighted scoring | Rules are rated low / medium / high / critical, not individual point values — consistent and easy to maintain |
| Combination bonuses | Co-occurring indicators that are more suspicious together than apart add bonus points |
| Warning panel | Prominent color-coded panel with icon, risk label, and an explicit action recommendation |
| Transparent scoring | Each finding shows rule ID, severity badge, and point contribution; the summary shows base + bonuses → final score |
| Deduplication | Rules in the same group (e.g. IP host and punycode) cannot both score to prevent double-counting |
| Precautions panel | Context-aware safety tips based on which rules triggered |
| Scan history | Up to 20 recent scans saved in `localStorage`; click any entry to re-analyze |
| Safe localStorage handling | All storage operations wrapped in `try/catch`; individual malformed entries are discarded |
| XSS prevention | All user-provided strings are HTML-escaped before insertion via `innerHTML` |
| No network requests | The submitted URL is never fetched, opened, or sent anywhere |
| Responsive layout | Two-column desktop layout collapses to single column on screens ≤ 768 px |
| Keyboard accessible | All interactive elements are keyboard-navigable with visible focus rings |

---

## Prerequisites

- A modern web browser (Chrome 80+, Firefox 75+, Edge 80+, Safari 13+)
- **Nothing else.** No Node.js, Python, pip, or any installation required.

---

## Running Locally

1. Download or clone this repository.
2. Open **`index.html`** in your browser:
   - **Windows**: Double-click `index.html`, or drag it into an open browser tab.
   - **macOS**: Double-click `index.html`, or right-click → Open With → your browser.
   - **Linux**: Run `xdg-open index.html` in a terminal, or drag into a browser tab.

No build step, no server, no dependencies to install.

---

## Project Structure

```
phishguard/
├── index.html        Main page — layout, warning panel, panels, accessibility markup
├── style.css         Dark cybersecurity theme, responsive grid, risk-level colors,
│                     warning panel variants, severity badge styles
├── script.js         Detection engine, scoring, combination bonuses, localStorage,
│                     warning panel renderer, UI rendering
├── REQUIREMENTS.md   Full requirements specification and test plan
└── requirements.txt  Documents that this project has zero Python dependencies
```

---

## Scoring System

### How scores are calculated

The scoring system uses three steps:

**Step 1 — Base points**  
Each triggered rule contributes points based on its *severity level*, not an arbitrary per-rule number:

| Severity | Weight | Meaning |
|----------|--------|---------|
| `low` | 10 | Minor indicator; also common in legitimate URLs |
| `medium` | 20 | Notable indicator; warrants caution |
| `high` | 35 | Strong signal; unusual in legitimate traffic |
| `critical` | 50 | Near-definitive red flag; almost never legitimate |

**Step 2 — Combination bonuses**  
When multiple indicators co-occur in patterns that are more alarming together than apart,
bonus points are added. Examples:

| Combination | Bonus | Reason |
|-------------|-------|--------|
| IP host + phishing keyword | +15 | Raw IP serving a credential page |
| Brand in subdomain + keyword | +15 | Classic impersonation + harvest structure |
| IP host + plain HTTP | +10 | No domain AND no encryption |
| @ symbol + keyword | +15 | Obfuscation trick + credential harvesting |
| Deep subdomains + brand + keyword | +15 | Full classic phishing URL structure |
| HTTP + non-standard port + keyword | +10 | Fake service on unusual port |
| Punycode + hyphen | +10 | Visual impersonation with hyphenated domain |
| Subdomain keyword + path keyword | +10 | Phishing language in both subdomain and path |

**Step 3 — Normalize**  
The total is clamped to a ceiling of 100. No division needed — the ceiling _is_ 100.

### Risk level thresholds

| Score | Level | Warning panel color | Recommendation |
|-------|-------|---------------------|----------------|
| 0 | **Clean** | Green | Verify domain before entering credentials |
| 1–24 | **Low Risk** | Yellow | Minor indicators; verify domain and HTTPS |
| 25–49 | **Medium Risk** | Orange | Suspicious indicators; avoid until verified |
| 50–74 | **High Risk** | Red | Multiple strong indicators; do not proceed without independent verification |
| 75–100 | **Critical Risk** | Bright red | Severe indicators; do not visit; report it |

### Detection rules

| Rule | Name | Severity | Notes |
|------|------|----------|-------|
| R-01 | IP Address Used as Hostname | High | dedup group: host-type |
| R-02 | URL Shortener Service | Medium | |
| R-03 | Excessively Long URL (>100 chars) | Low | |
| R-04 | Suspicious Keyword in Path or Query | Medium | |
| R-05 | Excessive Subdomain Depth (≥4 labels) | Medium | |
| R-06 | Hyphen in Registered Domain | Low | skipped for known shorteners |
| R-07 | Non-Standard Port | Medium | |
| R-08 | Plain HTTP — No Encryption | Medium | |
| R-09 | Brand Name Embedded in Subdomain | High | |
| R-10 | Misleading @ Symbol Before Hostname | Critical | |
| R-11 | Double-Slash in URL Path | Medium | |
| R-12 | Punycode / Internationalized Domain | High | dedup group: host-type |
| R-13 | Phishing Keywords in Subdomain Labels | High | |

---

## Warning Panel

The warning panel is the first element shown after analysis. It uses:
- A **distinctive icon** (✔ for clean/low, ⚠ for medium, ✖ for high/critical)
- A **color-coded border and background** matching the risk level
- A **bold risk label** with a plain-English summary (e.g. "HIGH — DANGER: This URL has multiple strong warning signs.")
- A **recommendation** — a specific, actionable instruction for the user

Color is not the only signal: every panel includes the text label and icon, ensuring accessibility for users with color-vision deficiency.

---

## Limitations of Heuristic Detection

PhishGuard is a **heuristic tool**. It cannot know for certain whether a URL is malicious or safe. Understand these limitations before relying on its output:

### False positives (legitimate URLs that score high)
- Long corporate intranet URLs may trigger the length rule.
- Sites legitimately hosted on non-standard ports (e.g. development servers) will trigger R-07.
- Security-related content pages (e.g. a blog post about "password security") may trigger R-04.
- Companies with hyphens in their official domain (e.g. `some-brand.com`) will trigger R-06.
- Internal tools served over plain HTTP on a trusted network will trigger R-08.

### False negatives (malicious URLs that score low)
- A phishing page on a clean-looking, newly registered HTTPS domain will score 0.
- Phishing URLs that use none of the detected structural patterns are invisible to this tool.
- URL shorteners can conceal any destination; the tool flags the shortener but cannot resolve it.
- Visual tricks that require rendering (deceptive page layout, fake logos) are not detectable.

### General limitations
- **No real-time intelligence**: PhishGuard does not consult any block list or threat feed.
- **No redirect resolution**: Shortened URLs are flagged but the destination is not revealed.
- **No public-suffix list**: The "registered domain" extraction uses a 2-label approximation.
  `example.co.uk` would incorrectly return `co.uk` as the registered domain.
- **localStorage scope**: Scan history is tied to the specific browser and device.
- **No guarantee in either direction**: A score of 0 does not mean a URL is safe; a score
  of 100 does not prove it is malicious.

---

## Academic Use Notice

This project was built for an educational cybersecurity bootcamp. It demonstrates client-side
URL analysis techniques and responsible communication of heuristic limitations. It is
**not** a production security tool and should not be used as the sole basis for security decisions.

---

*PhishGuard — For educational purposes only.*
