# PhishGuard — Phishing URL Risk Analyzer
## Requirements Document

---

## 1. Problem Statement

Phishing attacks trick users into visiting malicious websites by disguising harmful URLs as
trustworthy ones. Everyday users often cannot tell whether a URL is suspicious without technical
knowledge. PhishGuard provides a lightweight, client-side heuristic tool that helps users
understand *why* a URL might be risky by surfacing specific, explainable warning signs — no
backend, no paid API, no external data source required.

---

## 2. Objectives

1. Accept a URL string from the user and analyze it entirely in the browser.
2. Identify and explain known heuristic indicators of phishing URLs.
3. Produce a transparent, labeled risk score that users can trace back to specific findings.
4. Store recent scan history in `localStorage` so users can compare results across sessions.
5. Make the code readable enough that a bootcamp student can walk through every line in a review.

---

## 3. Scope

### In scope
- Client-side URL string analysis (no network requests to the submitted URL)
- Heuristic detection rules applied to the URL's structure and text
- Risk scoring based on the number and weight of triggered rules
- Scan history stored in `localStorage` (optional, gracefully degraded)
- Responsive single-page UI styled as a cybersecurity dashboard

### Out of scope
- Backend servers, databases, or authentication
- Machine learning or AI classification
- Live HTTP requests to submitted URLs
- Definitive malicious/safe verdicts
- Browser extensions or native apps

---

## 4. Functional Requirements

| ID   | Requirement |
|------|-------------|
| FR-1 | The user can type or paste any URL string into an input field. |
| FR-2 | Pressing **Analyze** or hitting **Enter** starts the analysis. |
| FR-3 | The app validates that the input is a plausibly formed URL before analyzing. |
| FR-4 | The app displays a numeric risk score (0–100) and a labeled risk level. |
| FR-5 | The app lists every triggered detection rule with a plain-English explanation. |
| FR-6 | The app displays "No issues found" when no rules trigger. |
| FR-7 | The analyzed URL and its risk score are saved to `localStorage` scan history. |
| FR-8 | The scan history panel lists recent scans; clicking one re-populates the input. |
| FR-9 | The user can clear all scan history with a single button. |
| FR-10 | All output is clearly labeled as a **heuristic estimate**, not a verdict. |

---

## 5. Non-Functional Requirements

| ID    | Requirement |
|-------|-------------|
| NFR-1 | The application runs entirely in a modern browser with no server. |
| NFR-2 | The app must not navigate to, fetch, or execute the submitted URL. |
| NFR-3 | `localStorage` failures (quota exceeded, private browsing blocked) are caught and handled silently; the app continues working without history. |
| NFR-4 | Malformed data found in `localStorage` is discarded safely. |
| NFR-5 | The UI is responsive and usable on screens from 320 px wide upward. |
| NFR-6 | Code is written without frameworks; plain HTML5, CSS3, and ES6 JavaScript only. |
| NFR-7 | No external fonts, CDN assets, or third-party scripts are loaded. |
| NFR-8 | Variable and function names are descriptive; each detection rule has an inline comment. |

---

## 6. Detection Rules

All rules are heuristic: triggering one or more rules **raises suspicion** but does not prove
maliciousness. A legitimate URL can trigger a rule; a malicious one may trigger none.

Each rule carries a **severity weight** used directly in scoring (no normalization divisor):
`low = 10 pts`, `medium = 20 pts`, `high = 35 pts`, `critical = 50 pts`.
A **combination bonus** is added when certain rule pairs fire together (9 bonuses defined in
`COMBO_BONUSES`). The final score is clamped to a ceiling of **100**.

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| R-01 | IP address host | critical | Hostname is a raw IPv4 or IPv6 address rather than a domain name. Phishing pages often use IPs to avoid registering a recognizable domain. |
| R-02 | URL shortener | medium | Domain matches a known shortener service (bit.ly, tinyurl.com, t.co, etc.). The true destination is hidden. |
| R-03 | Excessive URL length | low | Full URL is longer than 100 characters. Very long URLs obscure the true destination and are common in phishing campaigns. |
| R-04 | Suspicious keyword in path/query | medium | Path or query string contains words like `login`, `verify`, `secure`, `update`, `confirm`, `account`, `banking`, `password`, `signin`, `webscr`. |
| R-05 | Excessive subdomains | medium | Hostname contains 4 or more dot-separated labels (e.g. `a.b.c.example.com`). Attackers use deep subdomains to bury a familiar brand name near the left side. |
| R-06 | Hyphen in domain | low | The registered domain (eTLD+1) contains a hyphen. Legitimate brand domains rarely need hyphens; attackers use them to spoof (e.g. `paypal-secure.com`). |
| R-07 | Non-standard port | medium | URL specifies an explicit port other than 80 or 443. Most legitimate sites use standard ports. |
| R-08 | HTTP (not HTTPS) | low | Scheme is plain `http://`. Sensitive pages should use TLS. |
| R-09 | Brand impersonation keyword | high | Hostname (excluding the registered domain) contains a popular brand name: `paypal`, `apple`, `google`, `microsoft`, `amazon`, `facebook`, `netflix`, `instagram`, `bank`. |
| R-10 | Misleading @ symbol | critical | URL contains `@` before the hostname, which causes browsers to discard everything before `@` as credentials — a classic phishing trick. |
| R-11 | Double slash redirect | medium | URL path contains `//` after the authority, often used to confuse parsers and redirect to a different host. |
| R-12 | Homoglyph / punycode domain | high | Hostname starts with `xn--`, indicating an internationalized domain that may visually impersonate a Latin-script domain. |
| R-13 | Phishing keywords in subdomain | high | The subdomain labels themselves contain words like `login`, `verify`, `secure`, `account`, `auth`, or `banking`. Strongly suggests an impersonation domain was constructed to appear trustworthy. |

**Score ceiling: 100.** Severity weights are summed directly; combination bonuses are added on top,
then the result is clamped at 100. No normalization divisor is used.

### Risk Level Thresholds

| Score | Label | Badge color |
|-------|-------|-------------|
| 0 | Clean | Green |
| 1–24 | Low Risk | Yellow-green |
| 25–49 | Medium Risk | Orange |
| 50–74 | High Risk | Red-orange |
| 75–100 | Critical Risk | Red |

---

## 7. Limitations

- **Heuristics only.** The tool cannot look up real-time threat intelligence or block lists.
- **No rendering.** The tool does not open the URL, so it cannot detect malicious JavaScript, deceptive visual design, or redirect chains.
- **False positives.** Legitimate URLs (e.g., a long corporate intranet URL) may score medium.
- **False negatives.** A well-crafted phishing URL with a clean-looking domain will score low.
- **URL shorteners.** The tool flags the shortener but cannot resolve the true destination.
- **`localStorage` scope.** History is tied to the browser and device; it is not shared.
- **No persistence guarantee.** Users can clear browser storage at any time.

---

## 8. Test Plan

### 8.1 Input Validation Tests

| Test | Input | Expected outcome |
|------|-------|-----------------|
| T-01 | Empty string | Validation error: "Please enter a URL." |
| T-02 | Plain text with no scheme | Validation error or auto-prepend `http://` and analyze |
| T-03 | Valid HTTPS URL | Analysis proceeds normally |

### 8.2 Detection Rule Tests

| Test | URL | Rules expected to trigger |
|------|-----|--------------------------|
| T-10 | `http://192.168.1.1/login` | R-01 (IP host), R-04 (login keyword), R-08 (HTTP) |
| T-11 | `https://bit.ly/abc123` | R-02 (shortener) |
| T-12 | `http://paypal-secure.verify-account.com/update?user=john` | R-04, R-05, R-06, R-08, R-09 |
| T-13 | `https://xn--pypal-4ve.com/` | R-12 (punycode) |
| T-14 | `http://evil.com:8080/secure` | R-04, R-07, R-08 |
| T-15 | `https://www.google.com/` | No rules triggered, score = 0 |
| T-16 | `http://user@malicious.com/` | R-08, R-10 (@ symbol) |
| T-17 | Very long URL (>100 chars) | R-03 (excessive length) |

### 8.3 History Tests

| Test | Action | Expected outcome |
|------|--------|-----------------|
| T-20 | Analyze a URL | Appears in history panel |
| T-21 | Click history item | Re-populates input and re-runs analysis |
| T-22 | Clear history | History panel shows empty state |
| T-23 | Fill localStorage quota | App continues working; history silently disabled |

### 8.4 UI / Responsiveness Tests

| Test | Viewport | Expected outcome |
|------|----------|-----------------|
| T-30 | 320 px wide (mobile) | No horizontal scroll; inputs/buttons usable |
| T-31 | 768 px (tablet) | Two-column layout if applicable |
| T-32 | 1280 px (desktop) | Full dashboard layout |

---

*Document version 1.1 — updated after Phase 3 (13 rules, severity-weight scoring)*
