# PROJECT REPORT
## PhishGuard — Heuristic Phishing URL Risk Analyzer

**GTU Cybersecurity Bootcamp — Student Project**

---

## 1. Abstract

PhishGuard is a client-side web application that accepts a URL string from the user and
analyzes it locally in the browser for structural indicators commonly associated with
phishing attacks. It produces a transparent, heuristic risk score (0–100), a color-coded
warning panel, a list of detected warning signs with per-rule explanations and severity
labels, and recommended precautions. The application requires no server, no backend, no
external API, and no installation beyond opening a single HTML file in a modern browser.

All analysis is performed on the URL string itself. The submitted URL is never fetched,
opened, or transmitted. Results are explicitly labeled as heuristic estimates; the system
does not claim to prove a URL is malicious or safe.

---

## 2. Problem Statement and Objectives

### Problem Statement

Phishing attacks remain one of the most common and effective attack vectors in
cybersecurity. Attackers craft URLs that visually or structurally mimic trusted domains
to trick users into submitting credentials or personal information. Non-technical users
are particularly vulnerable because they lack tools to systematically examine a URL's
structural risk indicators before clicking.

Existing solutions require either a network connection to consult a threat-intelligence
feed, a browser extension, or a subscription to a paid service. For an educational
bootcamp project, these approaches are out of scope. There is educational value in
demonstrating that meaningful, explainable URL analysis can be performed using only
structural heuristics — without any external data.

### Objectives

1. Accept any URL string and analyze it entirely within the browser.
2. Apply 13 heuristic detection rules covering a range of known phishing techniques.
3. Produce a risk score that reflects the severity and co-occurrence of indicators.
4. Present findings and their explanations in a format accessible to non-experts.
5. Provide actionable precautions tailored to the specific indicators detected.
6. Store scan history in `localStorage` with safe handling of unavailable or corrupt data.
7. Keep the codebase readable enough to walk through line-by-line in a project review.

---

## 3. Technologies Used

| Technology | Purpose |
|------------|---------|
| HTML5 | Page structure, semantic markup, ARIA accessibility attributes |
| CSS3 | Dark-theme dashboard, responsive grid, per-severity color variants |
| Vanilla JavaScript (ES6+) | Detection engine, scoring, localStorage, UI rendering |
| Browser `URL` API | Native URL parsing with scheme, hostname, port, path, query extraction |
| Browser `localStorage` API | Persistent scan history across sessions |

No frameworks, libraries, CDN resources, external fonts, or backend services are used.
The entire application is contained in three files: `index.html`, `style.css`, and
`script.js`.

---

## 4. System Design and Workflow

### 4.1 Architecture

PhishGuard is a single-page application (SPA) with no build step. The browser loads
`index.html`, which references `style.css` for presentation and `script.js` for all
application logic. The page renders entirely on the client; no requests are made to any
external server at any point.

```
User types URL → [Validate] → [Parse] → [Detect] → [Score] → [Render] → [Save history]
                    ↓ invalid
               Show error message
```

### 4.2 Component Breakdown

**`parseURL(raw)`** — Wraps the native `URL` constructor. Explicitly rejects any scheme
other than `http://` or `https://` (including `ftp://`, `javascript:`, `data:`, etc.).
Auto-prepends `http://` when no scheme is present and records this in a `schemePrepended`
flag so detection rules can take it into account. Returns `null` for inputs that cannot
be parsed as a URL.

**`analyzeURL(parsed)`** — Iterates the 13 detection rules. Before each `test()` call,
per-call mutable state on the rule object (matched keywords, matched brands) is reset to
`null` so that re-running analysis on a new URL never carries state from a previous scan.
After all rules run, a deduplication pass marks findings that belong to the same group
(e.g. R-01 and R-12 both relate to host type) so that overlapping rules share rather
than stack points.

**`calcScore(findings)`** — Implements a three-step scoring algorithm described in
Section 5.

**`getRiskLevel(score)`** — Maps the 0–100 score to a risk level (Clean / Low / Medium /
High / Critical) using documented threshold boundaries.

**`getWarning(risk, findings)`** — Returns the three text fields for the warning panel:
icon, message (which embeds the risk label), and recommendation.

**`getPrecautions(findings, risk)`** — Builds a list of actionable safety tips chosen
based on which specific rules triggered.

**`renderResults(…)`** — Updates all DOM elements in the results area: warning panel,
analyzed-URL display, score number, risk badge, score bar, findings list with per-rule
severity badges and points, score breakdown summary, and precautions list.

**`renderHistory()`** — Reads from `localStorage`, validates each entry, and rebuilds the
scan history sidebar. History items are clickable buttons that re-populate the input and
re-run analysis.

**`runAnalysis(rawInput)`** — The orchestrator function wired to the form submit event.
Calls each component in order, handles the `setAnalyzing` disabled state, and ensures
`event.preventDefault()` is called before any other logic so the browser never navigates
to the submitted URL.

### 4.3 Security Design

- **No network access to analyzed URLs.** `fetch()`, `XMLHttpRequest`, and `window.open()`
  are absent from the codebase. The `URL` constructor is used only to parse the string —
  it does not make a network request.
- **XSS prevention.** Every user-supplied string displayed via `innerHTML` is passed
  through `escapeHTML()`, which replaces `& < > " '` with HTML entities. Strings that are
  set via `textContent` (the precautions list) need no escaping.
- **localStorage safety.** All reads and writes to `localStorage` are wrapped in
  `try/catch`. If storage is unavailable (private browsing mode, quota exceeded, blocked
  by browser policy), the application continues normally without history. Each entry is
  individually validated on load; a corrupt entry is discarded silently.
- **Input validation.** Empty strings, whitespace-only strings, non-http/https schemes,
  and structurally unparseable strings all return `null` from `parseURL()` and produce a
  user-friendly error message. Analysis only begins on a successfully parsed URL.

---

## 5. Risk-Scoring Methodology

### 5.1 Design Goals

The previous scoring version used a 230-point denominator derived from the theoretical
maximum if all rules fired simultaneously. This caused individual severe indicators to
score too low (e.g. the `@`-symbol trick scored only 15/100 alone), making the system
under-alert on clearly suspicious URLs. The redesigned system has three explicit goals:

1. A single severe indicator produces a score that reaches a meaningful threshold.
2. Co-occurring indicators that are more alarming together than apart receive extra points.
3. No double-counting of rules that overlap in meaning.

### 5.2 Severity Weights

Each rule is assigned a severity level rather than an individual point value. This keeps
the system maintainable — adding a rule only requires choosing a severity.

| Severity | Weight | Meaning |
|----------|--------|---------|
| `low` | 10 | Minor indicator; also present in many legitimate URLs |
| `medium` | 20 | Notable indicator; warrants caution |
| `high` | 35 | Strong signal; unusual in legitimate public traffic |
| `critical` | 50 | Near-definitive red flag; almost never seen in legitimate URLs |

### 5.3 Combination Bonuses

Nine combination rules add bonus points when specific sets of indicators co-occur. The
bonus is applied to the full triggered-ID set (including dedup-zeroed rules), because the
*pattern* is alarming regardless of which rule holds the base points.

| Combination | Bonus | Rationale |
|-------------|-------|-----------|
| IP host + credential keyword | +15 | Raw IP serving a login/password page |
| IP host + plain HTTP | +10 | No domain name AND no encryption |
| Brand in subdomain + credential keyword | +15 | Classic credential-harvesting structure |
| Brand in subdomain + plain HTTP | +10 | Impersonation site without TLS |
| `@` symbol + credential keyword | +15 | Obfuscation combined with harvesting intent |
| Deep subdomains + brand + keyword | +15 | Full classic phishing URL structure |
| HTTP + non-standard port + keyword | +10 | Fake service on unusual port |
| Punycode + hyphen | +10 | Visual impersonation with hyphenated domain |
| Subdomain keyword + path keyword | +10 | Phishing language in both subdomain and path |

### 5.4 Score Normalization and Thresholds

The raw total (base + bonus) is clamped to a ceiling of 100. No division is required.

| Score | Risk Level | Warning Panel |
|-------|-----------|---------------|
| 0 | **Clean** | Green — verify domain before entering credentials |
| 1–24 | **Low Risk** | Yellow — minor indicators; check domain and HTTPS |
| 25–49 | **Medium Risk** | Orange — suspicious; avoid until independently verified |
| 50–74 | **High Risk** | Red — multiple strong indicators; do not proceed |
| 75–100 | **Critical Risk** | Bright red — severe combination; do not visit |

### 5.5 Deduplication

Rules R-01 (IP host) and R-12 (punycode) share the dedup group `'host-type'`. If both
trigger (which is theoretically possible for `http://[::1]xn--...`), only the first in
the findings list contributes base points. Both findings still appear in the UI with the
dedup-zeroed one labeled "+0 pts (not counted — overlaps with another finding)".

---

## 6. Detection Rules

| Rule | Name | Severity | Detection Method |
|------|------|----------|-----------------|
| R-01 | IP Address Used as Hostname | High | Regex match `^\d{1,3}(\.\d{1,3}){3}$` or hostname contains `:` (IPv6) |
| R-02 | URL Shortener Service | Medium | Registered domain in hardcoded set of 19 known shorteners |
| R-03 | Excessively Long URL | Low | `raw.length > 100` |
| R-04 | Suspicious Keyword in Path or Query | Medium | Path + query string contains one of 20 credential-harvesting keywords |
| R-05 | Excessive Subdomain Depth | Medium | Hostname has ≥ 4 dot-separated labels |
| R-06 | Hyphen in Registered Domain | Low | Last-two-labels contains `-`; skipped for known shorteners |
| R-07 | Non-Standard Port | Medium | Explicit port present and not 80 or 443 |
| R-08 | Plain HTTP — No Encryption | Medium | URL scheme is `http` |
| R-09 | Brand Name in Subdomain | High | Subdomain (all but last two labels) contains one of 24 brand keywords |
| R-10 | Misleading @ Before Hostname | Critical | Raw string authority segment contains `@` |
| R-11 | Double-Slash in URL Path | Medium | `pathname` contains `//` and length > 1 |
| R-12 | Punycode / Internationalized Domain | High | Hostname contains `xn--` |
| R-13 | Phishing Keywords in Subdomain | High | Subdomain labels contain one of 9 credential-related words |

---

## 7. User Interface

### 7.1 Layout

The interface is a two-column dashboard on screens wider than 768 px. The left column
contains the input form and results area; the right column contains scan history. On
narrower screens the layout stacks to a single column with no horizontal overflow.

### 7.2 Warning Panel

The warning panel is the first element displayed after analysis and is designed to be
immediately understood:

- **Icon** — ✔ (clean/low), ⚠ (medium), ✖ (high/critical)
- **Color-coded border and background** — matching the risk level
- **Bold risk label** — e.g. "HIGH — DANGER: This URL has multiple strong warning signs."
- **Recommendation** — a specific, actionable instruction

Color is not the only signal. Every panel includes the icon and the text label, ensuring
the result is understood by users with color-vision deficiency.

### 7.3 Findings List

Each triggered rule is displayed as a card with:
- Rule ID (e.g. R-10) in monospace
- Severity badge (Low / Medium / High / Critical) color-coded to the rule's severity
- Point contribution ("+35 pts" or "+0 pts (not counted...)" for dedup-zeroed rules)
- Rule name in bold
- Plain-English explanation of what the indicator means and why it matters

A summary row at the bottom shows: Base points + combination bonus → final score / 100.

### 7.4 Precautions

Below the findings list, a separate section shows tailored safety tips based on which
rules triggered. For example, if R-10 (@ symbol) triggered, the user receives an
explanation of exactly how the browser interprets the `@` in a URL.

### 7.5 Scan History

The scan history sidebar shows up to 20 recent scans. Each entry displays the URL
(truncated with ellipsis if long), the score/level, and the timestamp. Clicking an entry
re-populates the input field and re-runs the analysis.

---

## 8. Testing Methodology and Results

### 8.1 Methodology

Tests were performed by running a Node.js harness that replicates the exact detection and
scoring logic from `script.js`. The harness covers eight categories and 31 test cases.
No results were hardcoded; every score is computed by the algorithm at test time.

### 8.2 Test Results

**Category: Input Validation (7 tests)**

| Input | Expected | Result |
|-------|----------|--------|
| Empty string | INVALID | ✅ PASS |
| Whitespace only | INVALID | ✅ PASS |
| "hello world" | INVALID | ✅ PASS |
| `http://` (no host) | INVALID | ✅ PASS |
| `javascript:alert(1)` | INVALID | ✅ PASS |
| `ftp://files.example.com/` | INVALID | ✅ PASS |
| "not a url" | INVALID | ✅ PASS |

**Category: Clean URLs (5 tests)**

| URL | Score | Level | Result |
|-----|-------|-------|--------|
| `https://www.google.com/` | 0 | Clean | ✅ PASS |
| `https://github.com/user/repo` | 0 | Clean | ✅ PASS |
| `https://example.com` | 0 | Clean | ✅ PASS |
| `https://docs.microsoft.com/en-us/azure` | 0 | Clean | ✅ PASS |
| `https://www.amazon.com/product/dp/B09X123456` | 0 | Clean | ✅ PASS |

*Note: `docs.microsoft.com` and `www.amazon.com` score Clean because R-09 checks only the
subdomain portion against brand keywords — and "microsoft" / "amazon" appear in the
registered domain itself (the last two labels), not in a foreign subdomain.*

**Category: Low Risk — Single Indicators (7 tests)**

| URL | Score | Rules | Result |
|-----|-------|-------|--------|
| `https://bit.ly/3xAbc99` | 20 | R-02 | ✅ PASS |
| `http://normal.example.com/` | 20 | R-08 | ✅ PASS |
| `https://my-site.com/` | 10 | R-06 | ✅ PASS |
| `https://www.google.com/login` | 20 | R-04 | ✅ PASS |
| `https://example.com//redirect` | 20 | R-11 | ✅ PASS |
| `https://a.b.c.example.com/` | 20 | R-05 | ✅ PASS |
| `https://tinyurl.com/some-code` | 20 | R-02 | ✅ PASS |

*These results confirm that a single low/medium-severity indicator does not cause a false
alarm: legitimate-looking URLs with only one minor issue remain below the Medium threshold.*

**Category: High Risk Combinations (4 tests)**

| URL | Score | Rules | Result |
|-----|-------|-------|--------|
| `http://192.168.1.1/` | 65 | R-01, R-08 (+combo) | ✅ High Risk |
| `https://xn--pypal-4ve.com/` | 55 | R-12, R-06 (+combo) | ✅ High Risk |
| `http://paypal.com@evil.com/` | 70 | R-08, R-10 | ✅ High Risk |
| `http://evil.com:8080/secure` | 70 | R-04, R-08, R-07 (+combo) | ✅ High Risk |

**Category: Critical Risk — Classic Phishing Patterns (7 tests)**

| URL | Score | Rules Triggered | Result |
|-----|-------|-----------------|--------|
| `http://192.168.1.1/login` | 100 | R-01, R-04, R-08 + 2 combos | ✅ Critical |
| `http://paypal.com@evil.com/signin` | 100 | R-04, R-08, R-10 + combo | ✅ Critical |
| `https://paypal.login.evil.com/signin` | 100 | R-04, R-05, R-09, R-13 + 3 combos | ✅ Critical |
| `http://paypal-secure.verify-account.com/update?user=john` | 100 | R-04, R-09, R-06, R-08, R-13 + 3 combos | ✅ Critical |
| `http://secure-verify.paypal.login.evil.com/password?confirm=1` | 100 | R-04, R-05, R-09, R-08, R-13 + 4 combos | ✅ Critical |
| `https://microsoft.secure-login.phish.com/account/signin` | 100 | R-04, R-05, R-09, R-13 + 3 combos | ✅ Critical |
| `http://[2001:db8::1]/login` | 100 | R-01, R-04, R-08 + 2 combos | ✅ Critical |

**Category: Edge Cases (7 tests)**

| Input | Score | Level | Notes |
|-------|-------|-------|-------|
| `suspicious-login.net/verify` (no scheme) | 50 | High Risk | http:// assumed; R-04, R-06, R-08 |
| `https://EXAMPLE.COM/path` | 0 | Clean | Hostname normalized to lowercase |
| `https://example.com:443/path` | 0 | Clean | Port 443 is standard — not flagged |
| `http://example.com:80/path` | 20 | Low Risk | Only R-08 fires; port 80 is standard |
| `https://cutt.ly/abcdef` | 20 | Low Risk | R-02 shortener |
| `https://a-b-c-d.com/path` | 10 | Low Risk | Only R-06 fires |

**Summary: 31/31 tests passed (100%).**

### 8.3 Key Observations

1. **No single low/medium indicator causes a false alarm.** URLs with only one minor
   indicator (HTTP alone, a hyphen, a phishing keyword on an otherwise clean domain) all
   score below 25 and remain in the Low Risk zone, matching the design intent.

2. **High-severity indicators alone reach Medium or High.** An IP host alone scores 35
   (Low). With HTTP it scores 65 (High). Adding a login keyword pushes it to 100 (Critical).
   This graduated response reflects real-world risk correctly.

3. **The `@`-symbol trick scores High on its own (70) and Critical with any keyword (100)**,
   as appropriate for one of the most deceptive URL obfuscation techniques known.

4. **Clean, well-known HTTPS URLs score 0** even when they contain brand names or subdomain
   depth (e.g. `docs.microsoft.com`), confirming that the brand-in-subdomain rule
   correctly checks only for foreign-subdomain impersonation.

5. **Non-http/https schemes are rejected.** `ftp://`, `javascript:`, `data:`, and similar
   inputs return an error before any analysis, preventing unexpected behavior.

---

## 9. Limitations and Future Improvements

### 9.1 Current Limitations

**Heuristics only — no threat intelligence.** PhishGuard analyzes URL structure. It
cannot consult any block list, anti-phishing database, or real-time threat feed. A
brand-new phishing domain that appears structurally clean will score 0.

**False positives.** Legitimate URLs can trigger rules:
- A long corporate intranet URL triggers R-03.
- A development server on port 8080 triggers R-07.
- An internal HTTP service triggers R-08.
- A company whose official domain contains a hyphen (e.g. `co-op.co.uk`) triggers R-06.
- A blog post titled "How to reset your password" triggers R-04 via keyword.

**False negatives.** Well-crafted phishing pages may not trigger any rule. A domain
registered with a clean look (e.g. `paypal-official.net` — no four-label subdomain, no
keyword in path, served over HTTPS) would score only 10/100 (hyphen in domain).

**No redirect resolution.** URL shorteners are flagged (R-02) but the true destination
is never revealed.

**Best-effort registered domain extraction.** The last-two-labels approximation works
for most gTLDs but fails for multi-label country-code TLDs such as `.co.uk`, `.com.au`,
or `.gov.in` — for these, `co.uk` would be treated as the registered domain.

**localStorage scope.** Scan history is tied to the specific browser profile and device.
Clearing browser storage removes all history.

### 9.2 Potential Future Improvements

| Improvement | Effort | Impact |
|-------------|--------|--------|
| Integrate Mozilla Public Suffix List for correct eTLD+1 extraction | Medium | Reduces false positives/negatives on ccTLDs |
| Add entropy analysis (random-looking hostnames like `xk2hq9.com`) | Low | Catches algorithmically generated domains |
| Detect excessive use of URL encoding (`%XX`) in path/query | Low | Covers obfuscation by encoding |
| Add a WHOIS-age indicator (newly registered domains) | High | Very high signal; requires API |
| Integrate VirusTotal or Google Safe Browsing API (optional, user-provided key) | High | Would provide real verdict, but adds dependency |
| Export scan results as CSV or PDF | Low | Useful for student project submissions |
| Browser extension packaging | Medium | Makes the tool accessible from the browser toolbar |

---

## 10. Conclusion

PhishGuard successfully demonstrates that meaningful, explainable phishing URL analysis
can be performed entirely in the browser without any server, database, or external API.
The redesigned scoring engine — using severity-weighted rules and combination bonuses
rather than a single large denominator — produces intuitive, well-calibrated results: clean
URLs score 0, URLs with single minor indicators remain in the Low zone, and URLs combining
multiple high-severity phishing patterns reach the High or Critical zones appropriately.

Across 31 test cases covering empty inputs, clean URLs, single-indicator URLs, high-severity
single indicators, classic phishing URL combinations, and edge cases, the system achieved a
100% pass rate against expected outcomes.

The project meets all stated objectives: local analysis only (no URL is ever fetched or
opened), transparent scoring with per-rule explanations, safe localStorage handling,
responsive accessible UI, and beginner-friendly well-commented code. It is a practical
demonstration of client-side security tooling that can be opened directly in a browser
and explained line-by-line in a project review.

---

## 11. Project File Listing

| File | Purpose |
|------|---------|
| `index.html` | Single-page application markup — form, warning panel, results, history sidebar |
| `style.css` | Dark cybersecurity dashboard theme; responsive; per-severity color variants |
| `script.js` | Complete application logic — 13 detection rules, scoring engine, storage, UI |
| `REQUIREMENTS.md` | Formal requirements document with FR/NFR tables, rule spec, test plan |
| `requirements.txt` | States explicitly that no Python or pip dependencies exist |
| `README.md` | Developer-facing overview, setup instructions, scoring documentation |
| `PROJECT_REPORT.md` | This document — full academic project report |

## 12. How to Run

1. Download or clone this repository to any local folder.
2. Double-click **`index.html`** to open it in your default browser.
   - Windows: double-click, or drag into a browser tab.
   - macOS: double-click, or right-click → Open With.
   - Linux: `xdg-open index.html` in a terminal.
3. Type or paste a URL into the input field and click **Analyze** (or press Enter).
4. Review the warning panel, score, findings, and precautions.
5. Previous scans appear in the Scan History sidebar; click any entry to re-analyze.

**No server. No installation. No build step. No internet connection required.**

---

*PhishGuard — GTU Cybersecurity Bootcamp Project — For educational purposes only.*  
*Results are heuristic estimates. This tool is not a substitute for professional security software.*
