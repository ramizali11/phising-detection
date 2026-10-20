/**
 * PhishGuard — script.js
 * Heuristic phishing URL risk analyzer.
 * Runs entirely in the browser. The submitted URL is NEVER fetched or opened.
 *
 * ── File structure ───────────────────────────────────────────────────────────
 *  1.  Configuration & constants
 *  2.  Detection rules          (RULES array)
 *  3.  URL parsing              parseURL()
 *  4.  Core analysis            analyzeURL()
 *  5.  Scoring engine           calcScore(), getRiskLevel()
 *        • Each rule has a severity (low / medium / high / critical).
 *        • Score starts at 0. Each triggered rule adds its severity weight.
 *        • Combination bonuses push the score higher when several indicators
 *          co-occur in ways that are more suspicious together than apart.
 *        • Dedup groups prevent rules that overlap in meaning from both scoring.
 *        • Final score is on a 0–100 scale.  Thresholds: ≥25 = Low,
 *          ≥50 = Medium, ≥75 = High.  Clean = 0.
 *  6.  Warning panel            getWarning()
 *  7.  Precautions              getPrecautions()
 *  8.  localStorage helpers     storageAvailable(), loadHistory(),
 *                               saveToHistory(), clearHistory()
 *  9.  UI helpers               escapeHTML(), showError(), clearError(),
 *                               setAnalyzing()
 * 10.  UI renderers             renderResults(), renderHistory()
 * 11.  Orchestrator             runAnalysis()
 * 12.  Event wiring & init
 */

'use strict';

/* ================================================================
   1. CONFIGURATION & CONSTANTS
   ================================================================ */

const MAX_HISTORY_ITEMS = 20;
const STORAGE_KEY       = 'phishguard_history';

/**
 * SEVERITY_WEIGHTS — maps a severity label to the raw points added to the score.
 *
 * The score formula sums these weights, adds combination bonuses, then maps
 * the total onto a 0–100 scale via a fixed ceiling (MAX_SCORE_CEILING).
 *
 * Choosing per-severity weights rather than per-rule weights keeps the system
 * maintainable: adding a new rule just requires picking a severity, and all
 * rules of the same severity automatically behave consistently.
 *
 *   low      →  10  (minor indicator; common in legitimate URLs too)
 *   medium   →  20  (notable indicator; warrants caution)
 *   high     →  35  (strong signal; unusual in legitimate traffic)
 *   critical →  50  (near-definitive red flag; almost never legitimate)
 */
const SEVERITY_WEIGHTS = {
  low:      10,
  medium:   20,
  high:     35,
  critical: 50,
};

/**
 * MAX_SCORE_CEILING — the raw-point total that maps to a normalized score of 100.
 *
 * Set to 100 so that the normalization is:  score = min(rawTotal, 100).
 * This means individual severe indicators reach meaningful thresholds on their
 * own, and combinations quickly push into High territory, without needing the
 * 230-point denominator that diluted scores in the previous version.
 */
const MAX_SCORE_CEILING = 100;

/* ================================================================
   2. DETECTION RULES
   ================================================================
   Each rule object:
     id        — unique ID (R-01 … R-13); referenced in combination checks
     name      — short label shown in the findings list
     severity  — 'low' | 'medium' | 'high' | 'critical'
     detail    — plain-English explanation of the indicator
     group     — (optional) dedup group: only the first triggered rule in a
                 group adds points; others still appear but are shown as +0
     test(p)   — receives ParsedURL, returns true if the indicator is detected
     getDetail(p) — (optional) richer message after test() has run
*/

/**
 * @typedef {Object} ParsedURL
 * @property {string}  raw              Original string the user typed
 * @property {URL}     url              Native URL object
 * @property {string}  scheme           "http" or "https"
 * @property {string}  hostname         Full hostname, lowercase
 * @property {string}  registeredDomain Best-effort eTLD+1, e.g. "example.com"
 * @property {string}  port             Explicit port string, or "" if default
 * @property {string}  path             URL pathname, e.g. "/login/verify"
 * @property {string}  query            URL search string, e.g. "?user=foo"
 * @property {boolean} schemePrepended  true when http:// was auto-added
 */

/* ── Known shortener registered domains ─────────────────────────── */
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'short.link', 'cutt.ly', 'rb.gy', 'tiny.cc',
  'shorturl.at', 'lnkd.in', 'bl.ink', 'rebrand.ly', 'clck.ru',
  'snip.ly', 'dub.sh', 'tiny.one',
]);

/* ── Brand names checked only in the *subdomain*, not the registered domain ─ */
const BRAND_KEYWORDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
  'netflix', 'instagram', 'wellsfargo', 'chase', 'citibank', 'dropbox',
  'linkedin', 'twitter', 'ebay', 'bankofamerica', 'hsbc', 'barclays',
  'steam', 'spotify', 'yahoo', 'outlook', 'onedrive', 'icloud',
];

/* ── Suspicious words in path or query string ───────────────────── */
const PHISH_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'confirm', 'account',
  'banking', 'password', 'signin', 'webscr', 'credential',
  'authenticate', 'validation', 'suspension', 'unlock', 'recover',
  'restore', 'reset', 'billing', 'payment', 'carddetail',
];

const RULES = [

  // ── Host type ─────────────────────────────────────────────────────

  {
    id: 'R-01',
    name: 'IP Address Used as Hostname',
    severity: 'high',
    group: 'host-type',
    detail: 'The hostname is a raw IP address instead of a domain name. ' +
            'Phishing pages often use IP addresses to avoid registering a recognizable domain.',
    test(p) {
      const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(p.hostname);
      const isIPv6 = p.hostname.includes(':');
      return isIPv4 || isIPv6;
    },
  },

  {
    id: 'R-12',
    name: 'Punycode / Internationalized Domain',
    severity: 'high',
    group: 'host-type',   // dedup with R-01; only one scores
    detail: 'The hostname uses "xn--" punycode encoding (an internationalized domain name). ' +
            'Attackers register IDNs that render visually close to legitimate brands ' +
            '(e.g. "xn--pypal-4ve.com" looks like "pypal.com").',
    test(p) {
      return p.hostname.toLowerCase().includes('xn--');
    },
  },

  // ── URL shorteners ────────────────────────────────────────────────

  {
    id: 'R-02',
    name: 'URL Shortener Service',
    severity: 'medium',
    detail: 'The domain is a known URL-shortening service. ' +
            'The true destination is hidden and cannot be evaluated without following the link.',
    test(p) {
      return SHORTENER_DOMAINS.has(p.registeredDomain);
    },
  },

  // ── URL length ────────────────────────────────────────────────────

  {
    id: 'R-03',
    name: 'Excessively Long URL',
    severity: 'low',
    detail: 'The URL exceeds 100 characters. Unusually long URLs are used to obscure ' +
            'the true destination by burying it in a long, confusing string.',
    test(p) {
      return p.raw.length > 100;
    },
    getDetail(p) {
      return `URL is ${p.raw.length} characters (threshold: 100). ` + this.detail;
    },
  },

  // ── Path / query keywords ─────────────────────────────────────────

  {
    id: 'R-04',
    name: 'Suspicious Keyword in Path or Query',
    severity: 'medium',
    _matchedKw: null,
    detail: 'The path or query string contains a word commonly found on credential-harvesting ' +
            'pages such as "login", "verify", "password", or "confirm".',
    test(p) {
      const haystack = (p.path + ' ' + p.query).toLowerCase();
      for (const kw of PHISH_KEYWORDS) {
        if (haystack.includes(kw)) { this._matchedKw = kw; return true; }
      }
      this._matchedKw = null;
      return false;
    },
    getDetail(p) {
      return `Matched keyword: "${this._matchedKw || '?'}". ` + this.detail;
    },
  },

  // ── Subdomain abuse ───────────────────────────────────────────────

  {
    id: 'R-05',
    name: 'Excessive Subdomain Depth',
    severity: 'medium',
    detail: 'The hostname has four or more dot-separated labels. ' +
            'Attackers use deep subdomain chains to bury a brand name on the left ' +
            'of a URL that they actually control (e.g. "paypal.com.evil.example.com").',
    test(p) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(p.hostname)) return false;  // IPs handled by R-01
      return p.hostname.split('.').length >= 4;
    },
  },

  {
    id: 'R-09',
    name: 'Brand Name Embedded in Subdomain',
    severity: 'high',
    _matchedBrand: null,
    detail: 'A well-known brand name appears in the subdomain, while the registered domain ' +
            'belongs to a different entity. This tricks users into thinking the URL is ' +
            'owned by that brand (e.g. "paypal.login.evil.com").',
    test(p) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(p.hostname)) return false;
      const parts = p.hostname.split('.');
      if (parts.length < 3) { this._matchedBrand = null; return false; }
      const subdomain = parts.slice(0, -2).join('.').toLowerCase();
      for (const brand of BRAND_KEYWORDS) {
        if (subdomain.includes(brand)) { this._matchedBrand = brand; return true; }
      }
      this._matchedBrand = null;
      return false;
    },
    getDetail(p) {
      return `Brand "${this._matchedBrand || '?'}" found in subdomain. ` + this.detail;
    },
  },

  // ── Domain structure ──────────────────────────────────────────────

  {
    id: 'R-06',
    name: 'Hyphen in Registered Domain',
    severity: 'low',
    detail: 'The registered domain contains a hyphen. Legitimate brand domains rarely ' +
            'use hyphens; attackers use them to spoof (e.g. "paypal-secure.com").',
    test(p) {
      if (SHORTENER_DOMAINS.has(p.registeredDomain)) return false; // already flagged by R-02
      return p.registeredDomain.includes('-');
    },
  },

  // ── Scheme ────────────────────────────────────────────────────────

  {
    id: 'R-08',
    name: 'Plain HTTP — No Encryption',
    severity: 'medium',
    detail: 'The URL uses http:// instead of https://. Without TLS, data sent to this ' +
            'page can be intercepted. Legitimate login and banking pages always use HTTPS.',
    test(p) {
      return p.scheme === 'http';
    },
    getDetail(p) {
      if (p.schemePrepended) {
        return 'No scheme was provided — http:// was assumed. ' + this.detail;
      }
      return this.detail;
    },
  },

  // ── Port ──────────────────────────────────────────────────────────

  {
    id: 'R-07',
    name: 'Non-Standard Port',
    severity: 'medium',
    detail: 'An explicit port other than 80 or 443 is specified. Most public-facing ' +
            'legitimate websites use only standard ports.',
    test(p) {
      return p.port !== '' && p.port !== '80' && p.port !== '443';
    },
    getDetail(p) {
      return `Port ${p.port} detected. ` + this.detail;
    },
  },

  // ── Obfuscation tricks ────────────────────────────────────────────

  {
    id: 'R-10',
    name: 'Misleading @ Symbol Before Hostname',
    severity: 'critical',
    detail: 'The URL contains "@" before the hostname. Browsers discard everything ' +
            'before "@" as credentials, so "http://paypal.com@evil.com/" navigates to ' +
            '"evil.com", not "paypal.com". This is a well-known phishing trick.',
    test(p) {
      const afterScheme = p.raw.replace(/^[a-z][a-z0-9+\-.]*:\/\//i, '');
      const authority   = afterScheme.split(/[/?#]/)[0];
      return authority.includes('@');
    },
  },

  {
    id: 'R-11',
    name: 'Double-Slash in URL Path',
    severity: 'medium',
    detail: 'The URL path contains "//" which can confuse parsers and is sometimes used ' +
            'to embed a redirect to a different host.',
    test(p) {
      return p.path.length > 1 && p.path.includes('//');
    },
  },

  // ── Extra structural indicators ───────────────────────────────────

  {
    id: 'R-13',
    name: 'Multiple Subdomains with Suspicious Keywords',
    severity: 'high',
    detail: 'The subdomain portion itself contains phishing-related keywords like ' +
            '"secure", "login", or "verify". This combination strongly suggests the ' +
            'domain was constructed to impersonate a trusted service.',
    test(p) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(p.hostname)) return false;
      const parts = p.hostname.split('.');
      if (parts.length < 3) return false;
      const subdomain = parts.slice(0, -2).join('.').toLowerCase();
      // Check for phishing keywords in the subdomain labels (not path)
      const subdomainKeywords = [
        'login', 'verify', 'secure', 'account', 'update',
        'signin', 'confirm', 'auth', 'banking',
      ];
      return subdomainKeywords.some(kw => subdomain.includes(kw));
    },
  },

];

/* ================================================================
   3. URL PARSING
   ================================================================ */

/**
 * parseURL — wraps the native URL API, extracts fields used by rules.
 * Auto-prepends http:// when no scheme is present and records this.
 * Returns null when the string cannot be parsed as a URL at all.
 * @param {string} raw
 * @returns {ParsedURL|null}
 */
function parseURL(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  // Reject any non-http/https scheme explicitly before trying to parse.
  // This covers ftp://, javascript:, data:, mailto:, etc.
  // We only accept strings that either have no scheme or have http:// / https://.
  const schemeMatch = trimmed.match(/^([a-z][a-z0-9+\-.]*):\/\//i);
  if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
    return null;   // unsupported scheme — reject silently
  }

  const hasScheme = /^https?:\/\//i.test(trimmed);
  const toParse   = hasScheme ? trimmed : 'http://' + trimmed;

  let url;
  try {
    url = new URL(toParse);
  } catch (_) {
    return null;
  }

  if (!url.hostname) return null;

  const hostname = url.hostname.toLowerCase();

  // Best-effort registered domain: last two dot-separated labels.
  // Good enough for our heuristics; no public-suffix list required.
  const parts = hostname.split('.');
  const registeredDomain = parts.length >= 2
    ? parts.slice(-2).join('.')
    : hostname;

  return {
    raw:              trimmed,
    url,
    scheme:           url.protocol.replace(':', '').toLowerCase(),
    hostname,
    registeredDomain,
    port:             url.port,
    path:             url.pathname,
    query:            url.search,
    schemePrepended:  !hasScheme,
  };
}

/* ================================================================
   4. CORE ANALYSIS
   ================================================================ */

/**
 * analyzeURL — runs all rules against a parsed URL.
 * Resets per-call mutable state before each test, then applies dedup.
 *
 * @param {ParsedURL} parsed
 * @returns {Array<{rule, detailMessage, dedupZero: boolean}>}
 */
function analyzeURL(parsed) {
  const findings = [];

  for (const rule of RULES) {
    // Reset per-call state stored on rule objects
    if ('_matchedKw'    in rule) rule._matchedKw    = null;
    if ('_matchedBrand' in rule) rule._matchedBrand = null;

    if (rule.test(parsed)) {
      const detailMessage = typeof rule.getDetail === 'function'
        ? rule.getDetail(parsed)
        : rule.detail;
      findings.push({ rule, detailMessage, dedupZero: false });
    }
  }

  // Dedup: within a group, only the first triggered rule scores
  const seenGroups = new Set();
  for (const finding of findings) {
    const g = finding.rule.group;
    if (g) {
      finding.dedupZero = seenGroups.has(g);
      seenGroups.add(g);
    }
  }

  return findings;
}

/* ================================================================
   5. SCORING ENGINE
   ================================================================
   Design goals
   ────────────
   1. A single severe indicator (e.g. @ trick, IP host) produces a meaningful
      score on its own — not diluted to ~15 % by a large denominator.
   2. Suspicious *combinations* score higher than the sum of their parts, to
      reflect that co-occurrence is more alarming than any indicator alone.
   3. No double-counting: dedup groups ensure overlapping rules share points.
   4. The output is always an integer 0–100.

   How it works
   ────────────
   Step A — Base points: sum SEVERITY_WEIGHTS for each non-deduped finding.
   Step B — Combination bonus: scan COMBO_BONUSES and add bonus when a combo
            of rule IDs all triggered (regardless of dedup status, because the
            *pattern* matters even if one rule's base points were zeroed).
   Step C — Normalize: clamp to MAX_SCORE_CEILING (100) so score stays 0–100.
            No division needed; the ceiling is already 100.

   Severity weights (from SEVERITY_WEIGHTS):
     low = 10 · medium = 20 · high = 35 · critical = 50

   Example base totals before combination bonus:
     @ trick alone (critical):      50 → score 50  (Medium)
     IP + HTTP (high + medium):     55 → score 55  (Medium–High boundary)
     IP + login + HTTP:             75 → score 75  (High)
     Brand-in-subdomain + keyword:  55 → score 55  + combo bonus → higher
*/

/**
 * COMBO_BONUSES — extra points when specific rule combinations all trigger.
 * bonus  — added to the raw total
 * reason — shown in the score breakdown (not currently displayed but useful
 *          for debugging and future UI work)
 *
 * Combos are checked against the full set of triggered rule IDs (including
 * dedup-zeroed ones), because the *pattern* is alarming regardless of which
 * rule claimed the base points.
 */
const COMBO_BONUSES = [
  {
    // IP address + a phishing keyword in the path: very strong signal
    ids: ['R-01', 'R-04'],
    bonus: 15,
    reason: 'IP host combined with credential-harvesting keyword',
  },
  {
    // IP address + plain HTTP: no encryption and no domain — suspicious together
    ids: ['R-01', 'R-08'],
    bonus: 10,
    reason: 'IP host combined with plain HTTP',
  },
  {
    // Brand impersonation in subdomain + phishing keyword: classic combo
    ids: ['R-09', 'R-04'],
    bonus: 15,
    reason: 'Brand in subdomain combined with credential keyword',
  },
  {
    // Brand impersonation + plain HTTP: impersonation without TLS
    ids: ['R-09', 'R-08'],
    bonus: 10,
    reason: 'Brand in subdomain combined with plain HTTP',
  },
  {
    // @ trick + any keyword — the @ trick is already critical, adding keyword confirms intent
    ids: ['R-10', 'R-04'],
    bonus: 15,
    reason: '@ symbol obfuscation combined with credential keyword',
  },
  {
    // Excessive subdomains + brand + keyword: full classic phishing structure
    ids: ['R-05', 'R-09', 'R-04'],
    bonus: 15,
    reason: 'Deep subdomain chain with brand name and credential keyword',
  },
  {
    // HTTP + non-standard port + keyword: fake service on unusual port
    ids: ['R-08', 'R-07', 'R-04'],
    bonus: 10,
    reason: 'Unencrypted non-standard port with credential keyword',
  },
  {
    // Punycode + hyphen: visual impersonation with hyphenated domain
    ids: ['R-12', 'R-06'],
    bonus: 10,
    reason: 'Punycode domain combined with hyphenated registered domain',
  },
  {
    // Subdomain keyword + phishing keyword in path: double-keyword presence
    ids: ['R-13', 'R-04'],
    bonus: 10,
    reason: 'Phishing keyword in both subdomain and path',
  },
];

/**
 * calcScore — computes the final 0–100 risk score.
 *
 * @param {Array<{rule, dedupZero: boolean}>} findings
 * @returns {{ score: number, rawBase: number, comboBonus: number, breakdown: string[] }}
 */
function calcScore(findings) {
  // Step A: base points from non-deduped findings
  const rawBase = findings.reduce((sum, f) => {
    return sum + (f.dedupZero ? 0 : SEVERITY_WEIGHTS[f.rule.severity]);
  }, 0);

  // Build a set of all triggered rule IDs (including dedup-zeroed) for combo matching
  const triggeredIds = new Set(findings.map(f => f.rule.id));

  // Step B: combination bonuses
  let comboBonus = 0;
  const breakdown = [];
  for (const combo of COMBO_BONUSES) {
    if (combo.ids.every(id => triggeredIds.has(id))) {
      comboBonus += combo.bonus;
      breakdown.push(`+${combo.bonus} (${combo.reason})`);
    }
  }

  // Step C: clamp to ceiling
  const score = Math.min(rawBase + comboBonus, MAX_SCORE_CEILING);

  return { score, rawBase, comboBonus, breakdown };
}

/**
 * getRiskLevel — maps a 0–100 score to a risk label and CSS class.
 *
 * Thresholds (documented here for easy review):
 *   0       → Clean  (no indicators at all)
 *   1–24    → Low    (minor indicators only; worth noting but not alarming)
 *   25–49   → Medium (notable indicators; verify before visiting)
 *   50–74   → High   (strong indicators; avoid unless independently verified)
 *   75–100  → Critical (severe combination; treat as malicious)
 *
 * @param {number} score
 * @returns {{ label: string, cssClass: string }}
 */
function getRiskLevel(score) {
  if (score === 0)  return { label: 'Clean',         cssClass: 'clean'    };
  if (score < 25)   return { label: 'Low Risk',       cssClass: 'low'      };
  if (score < 50)   return { label: 'Medium Risk',    cssClass: 'medium'   };
  if (score < 75)   return { label: 'High Risk',      cssClass: 'high'     };
  return              { label: 'Critical Risk',     cssClass: 'critical' };
}

/* ================================================================
   6. WARNING PANEL
   ================================================================
   Returns the three text pieces needed to fill the warning panel:
     icon        — single emoji/symbol representing severity
     message     — one-sentence summary of what was found
     recommendation — explicit action the user should take
*/

/**
 * @typedef {Object} WarningContent
 * @property {string} icon
 * @property {string} message
 * @property {string} recommendation
 */

/**
 * getWarning — produces warning panel content appropriate for the risk level.
 * @param {{ label: string, cssClass: string }} risk
 * @param {Array<{rule}>} findings
 * @returns {WarningContent}
 */
function getWarning(risk, findings) {
  const triggered = new Set(findings.map(f => f.rule.id));

  switch (risk.cssClass) {
    case 'clean':
      return {
        icon: '✔',
        message: 'LOW — No major warning signs detected.',
        recommendation:
          'This does not guarantee safety. Always verify the domain carefully ' +
          'before entering passwords or personal information.',
      };

    case 'low':
      return {
        icon: '⚠',
        message: 'LOW — No major warning signs detected, but minor indicators are present.',
        recommendation:
          'Proceed with caution. Verify that the domain is spelled correctly and ' +
          'that the page is served over HTTPS before submitting any information.',
      };

    case 'medium':
      return {
        icon: '⚠',
        message: 'MEDIUM — Caution: This URL has suspicious indicators.',
        recommendation:
          'Avoid visiting this URL until you have independently verified the source. ' +
          'Do not enter passwords, payment details, or personal information.',
      };

    case 'high':
      return {
        icon: '✖',
        message: 'HIGH — DANGER: This URL has multiple strong warning signs.',
        recommendation:
          'Do not visit this URL unless you have independently verified it is legitimate. ' +
          'It displays characteristics commonly associated with phishing pages.',
      };

    case 'critical':
      return {
        icon: '✖',
        message: 'CRITICAL — DANGER: This URL displays severe phishing indicators.',
        recommendation:
          'Do not visit this URL. It shows a dangerous combination of deception techniques. ' +
          'If you received it in an email or message, report it to your email provider ' +
          'and to phishtank.com.',
      };

    default:
      return {
        icon: '?',
        message: 'Risk level could not be determined.',
        recommendation: 'Treat this URL with caution.',
      };
  }
}

/* ================================================================
   7. PRECAUTIONS
   ================================================================ */

/**
 * getPrecautions — context-aware safety tips based on triggered rules.
 * @param {Array<{rule}>} findings
 * @param {{ label: string, cssClass: string }} risk
 * @returns {string[]}
 */
function getPrecautions(findings, risk) {
  const tips = [];
  const triggered = new Set(findings.map(f => f.rule.id));

  if (risk.cssClass === 'clean') {
    tips.push(
      'No heuristic indicators were detected. However, a clean score does not guarantee ' +
      'safety — well-crafted phishing pages may look perfectly normal. Always verify the ' +
      'domain is exactly correct before entering credentials.'
    );
    return tips;
  }

  tips.push(
    'Do not enter passwords, payment details, or personal information on this page ' +
    'until you have independently confirmed it is legitimate.'
  );

  if (triggered.has('R-10')) {
    tips.push(
      'The "@" character before the hostname is a well-known phishing trick. ' +
      'Everything before "@" is treated as credentials by the browser; the real ' +
      'destination is what comes AFTER "@". This URL may be navigating to a different ' +
      'site than it appears.'
    );
  }
  if (triggered.has('R-01')) {
    tips.push(
      'The site is hosted at a raw IP address. Legitimate public services almost always ' +
      'use domain names. Unless you are accessing an internal network resource, treat this URL ' +
      'with high suspicion.'
    );
  }
  if (triggered.has('R-12')) {
    tips.push(
      'The internationalized domain (punycode) may render visually close to a trusted brand ' +
      'in some fonts. Check the actual domain characters carefully in your browser address bar.'
    );
  }
  if (triggered.has('R-09')) {
    tips.push(
      'Look at the full domain, not just the subdomain. "paypal.evil.com" is registered to ' +
      '"evil.com", not PayPal. Verify that the registered domain (the last two parts) is the ' +
      'brand\'s official domain.'
    );
  }
  if (triggered.has('R-13')) {
    tips.push(
      'Phishing-related words appear in the subdomain itself (e.g. "secure-login.evil.com"). ' +
      'The subdomain does not define ownership — only the registered domain does.'
    );
  }
  if (triggered.has('R-02')) {
    tips.push(
      'This is a shortened URL. The true destination is hidden. Use a safe link-preview ' +
      'service (e.g. checkshorturl.com) to reveal the real destination before clicking.'
    );
  }
  if (triggered.has('R-08')) {
    tips.push(
      'The page is served over plain HTTP with no encryption. Never submit login credentials ' +
      'or payment information over HTTP. Look for "https://" and the padlock icon first.'
    );
  }
  if (triggered.has('R-06')) {
    tips.push(
      'Hyphens in a domain name are often used to mimic a brand (e.g. "paypal-secure.com"). ' +
      'Confirm the domain matches the brand\'s exact official spelling.'
    );
  }
  if (triggered.has('R-07')) {
    tips.push(
      'The non-standard port suggests this is not a normal public website. Contact the ' +
      'organisation through a known-good channel before proceeding.'
    );
  }
  if (risk.cssClass === 'high' || risk.cssClass === 'critical') {
    tips.push(
      'Multiple high-confidence indicators are present. Consider reporting this URL to ' +
      'your IT security team or to phishtank.com.'
    );
  }

  return tips;
}

/* ================================================================
   8. LOCALSTORAGE HELPERS
   ================================================================
   All operations are wrapped in try/catch.
   If localStorage is unavailable the app works without history.
*/

function storageAvailable() {
  try {
    const k = '__phishguard_test__';
    localStorage.setItem(k, '1');
    localStorage.removeItem(k);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * loadHistory — reads and validates stored history.
 * Discards the whole array if it is not an array; discards individual
 * entries that are missing required fields.
 */
function loadHistory() {
  if (!storageAvailable()) return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(e =>
      e &&
      typeof e.url       === 'string' && e.url.length > 0 &&
      typeof e.score     === 'number' && isFinite(e.score) &&
      typeof e.level     === 'string' &&
      typeof e.cssClass  === 'string' &&
      typeof e.timestamp === 'string'
    );
  } catch (_) {
    return [];
  }
}

function saveToHistory(entry) {
  if (!storageAvailable()) return;
  try {
    const history = loadHistory();
    const newEntry = {
      url:       String(entry.url),
      score:     Number(entry.score),
      level:     String(entry.level),
      cssClass:  String(entry.cssClass),
      timestamp: new Date().toLocaleString(),
    };
    const updated = [newEntry, ...history].slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (_) { /* quota or access error — ignore */ }
}

function clearHistory() {
  if (!storageAvailable()) return;
  try { localStorage.removeItem(STORAGE_KEY); } catch (_) { /* ignore */ }
}

/* ================================================================
   9. UI HELPERS
   ================================================================ */

/**
 * escapeHTML — converts special characters to HTML entities.
 * Must be used whenever user-provided strings are inserted via innerHTML.
 */
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showError(message) {
  const el = document.getElementById('input-error');
  el.textContent = message;
  el.hidden = false;
  el.focus();
}

function clearError() {
  const el = document.getElementById('input-error');
  el.textContent = '';
  el.hidden = true;
}

function setAnalyzing(on) {
  const btn = document.getElementById('analyze-btn');
  if (on) {
    btn.textContent = 'Analyzing…';
    btn.disabled    = true;
    btn.setAttribute('aria-busy', 'true');
  } else {
    btn.textContent = 'Analyze';
    btn.disabled    = false;
    btn.removeAttribute('aria-busy');
  }
}

/* ================================================================
   10. UI RENDERERS
   ================================================================ */

/**
 * renderResults — populates every section of the results area.
 *
 * @param {ParsedURL}  parsed
 * @param {Array}      findings
 * @param {number}     score         0–100
 * @param {number}     rawBase       sum of severity weights before bonuses
 * @param {number}     comboBonus    extra points from combination rules
 * @param {string[]}   comboBreakdown human-readable bonus descriptions
 * @param {{ label: string, cssClass: string }} risk
 * @param {WarningContent} warning
 * @param {string[]}   precautions
 */
function renderResults(parsed, findings, score, rawBase, comboBonus, comboBreakdown, risk, warning, precautions) {

  // ── Show results area
  document.getElementById('results-area').hidden = false;

  // ── Warning panel
  const panelEl      = document.getElementById('warning-panel');
  const iconEl       = document.getElementById('warning-icon');
  const levelEl      = document.getElementById('warning-level');
  const messageEl    = document.getElementById('warning-message');
  const recommEl     = document.getElementById('warning-recommendation');

  panelEl.className   = 'warning-panel warning-' + risk.cssClass;
  iconEl.textContent  = warning.icon;
  levelEl.textContent = warning.message;      // includes level prefix e.g. "HIGH — DANGER…"
  messageEl.hidden    = true;                 // message is embedded in levelEl
  recommEl.textContent = warning.recommendation;

  // ── Analyzed URL
  document.getElementById('analyzed-url-display').textContent = parsed.raw;
  const noteEl = document.getElementById('scheme-note');
  if (parsed.schemePrepended) {
    noteEl.textContent = '(No scheme provided — http:// was assumed)';
    noteEl.hidden = false;
  } else {
    noteEl.hidden = true;
  }

  // ── Score number
  const scoreNumEl       = document.getElementById('score-number');
  scoreNumEl.textContent = score;
  scoreNumEl.className   = 'score-number ' + risk.cssClass;

  // ── Risk badge
  const badgeEl       = document.getElementById('risk-badge');
  badgeEl.textContent = risk.label;
  badgeEl.className   = 'risk-badge ' + risk.cssClass;

  // ── Score bar
  const barFillEl = document.getElementById('score-bar-fill');
  barFillEl.style.width = score + '%';
  barFillEl.className   = 'score-bar-fill ' + risk.cssClass;
  barFillEl.setAttribute('aria-valuenow', score);

  // ── Score card border
  document.getElementById('score-card').className = 'score-card risk-' + risk.cssClass;

  // ── Findings list
  const listEl       = document.getElementById('findings-list');
  const noFindingsEl = document.getElementById('no-findings-msg');
  listEl.innerHTML   = '';

  if (findings.length === 0) {
    noFindingsEl.hidden = false;
  } else {
    noFindingsEl.hidden = true;

    for (const { rule, detailMessage, dedupZero } of findings) {
      const pts = dedupZero ? 0 : SEVERITY_WEIGHTS[rule.severity];
      const li  = document.createElement('li');
      li.className = 'finding-item severity-' + rule.severity;

      const severityLabel = rule.severity.charAt(0).toUpperCase() + rule.severity.slice(1);
      const pointsLabel   = dedupZero
        ? `+0 pts <span class="finding-dedup">(not counted — overlaps with another finding)</span>`
        : `+${pts} pts`;

      li.innerHTML = `
        <div class="finding-header">
          <span class="finding-rule-id">${escapeHTML(rule.id)}</span>
          <span class="finding-severity finding-severity-${escapeHTML(rule.severity)}">${escapeHTML(severityLabel)}</span>
          <span class="finding-points">${pointsLabel}</span>
        </div>
        <p class="finding-name">${escapeHTML(rule.name)}</p>
        <p class="finding-detail">${escapeHTML(detailMessage)}</p>
      `;
      listEl.appendChild(li);
    }

    // Score breakdown summary row
    const summaryEl = document.createElement('li');
    summaryEl.className = 'finding-summary';
    let summaryHtml = `Base: <strong>${rawBase}</strong>`;
    if (comboBonus > 0) {
      summaryHtml += ` + combination bonus: <strong>+${comboBonus}</strong>`;
      for (const line of comboBreakdown) {
        summaryHtml += ` <span class="combo-line">${escapeHTML(line)}</span>`;
      }
    }
    summaryHtml += ` → Score: <strong>${score}</strong> / 100`;
    summaryEl.innerHTML = `<span>${summaryHtml}</span>`;
    listEl.appendChild(summaryEl);
  }

  // ── Precautions
  const precautionsList  = document.getElementById('precautions-list');
  precautionsList.innerHTML = '';
  for (const tip of precautions) {
    const li = document.createElement('li');
    li.className   = 'precaution-item';
    li.textContent = tip;     // textContent — safe, no injection risk
    precautionsList.appendChild(li);
  }

  // Scroll results into view
  document.getElementById('results-area')
    .scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * renderHistory — rebuilds the scan history sidebar from localStorage.
 */
function renderHistory() {
  const listEl    = document.getElementById('history-list');
  const emptyEl   = document.getElementById('history-empty-msg');
  const unavailEl = document.getElementById('history-unavailable-msg');

  listEl.innerHTML = '';

  if (!storageAvailable()) {
    emptyEl.hidden   = true;
    unavailEl.hidden = false;
    return;
  }

  const history = loadHistory();

  if (history.length === 0) {
    emptyEl.hidden   = false;
    unavailEl.hidden = true;
    return;
  }

  emptyEl.hidden   = true;
  unavailEl.hidden = true;

  for (const entry of history) {
    const btn   = document.createElement('button');
    btn.type      = 'button';
    btn.className = 'history-item';
    btn.title     = 'Re-analyze: ' + entry.url;

    const safeScore = Math.max(0, Math.min(100, Math.round(Number(entry.score))));

    btn.innerHTML = `
      <span class="history-item-url">${escapeHTML(entry.url)}</span>
      <span class="history-item-meta">
        <span class="history-item-score ${escapeHTML(entry.cssClass || 'clean')}">
          ${safeScore}/100 — ${escapeHTML(entry.level)}
        </span>
        <span class="history-item-time">${escapeHTML(entry.timestamp)}</span>
      </span>
    `;

    btn.addEventListener('click', () => {
      document.getElementById('url-input').value = entry.url;
      runAnalysis(entry.url);
      document.getElementById('analyze-form')
        .scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    listEl.appendChild(btn);
  }
}

/* ================================================================
   11. ORCHESTRATOR
   ================================================================ */

/**
 * runAnalysis — full pipeline: validate → parse → detect → score →
 *               warning → precautions → render → save → refresh history.
 * @param {string} rawInput
 */
function runAnalysis(rawInput) {
  clearError();

  const trimmed = rawInput.trim();
  if (!trimmed) {
    showError('Please enter a URL before clicking Analyze.');
    return;
  }

  setAnalyzing(true);

  const parsed = parseURL(trimmed);
  if (!parsed) {
    setAnalyzing(false);
    showError(
      'That doesn\'t look like a valid URL. ' +
      'Try starting with "https://", e.g. "https://example.com".'
    );
    return;
  }

  const findings                                    = analyzeURL(parsed);
  const { score, rawBase, comboBonus, breakdown }   = calcScore(findings);
  const risk                                        = getRiskLevel(score);
  const warning                                     = getWarning(risk, findings);
  const precautions                                 = getPrecautions(findings, risk);

  renderResults(
    parsed, findings,
    score, rawBase, comboBonus, breakdown,
    risk, warning, precautions
  );

  saveToHistory({ url: parsed.raw, score, level: risk.label, cssClass: risk.cssClass });
  renderHistory();
  setAnalyzing(false);
}

/* ================================================================
   12. EVENT WIRING & INITIALIZATION
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {

  // Form submit covers both button click and Enter key in the input
  document.getElementById('analyze-form').addEventListener('submit', event => {
    event.preventDefault();   // IMPORTANT: never navigate to the submitted URL
    runAnalysis(document.getElementById('url-input').value);
  });

  document.getElementById('clear-history-btn').addEventListener('click', () => {
    clearHistory();
    renderHistory();
  });

  renderHistory();
});
