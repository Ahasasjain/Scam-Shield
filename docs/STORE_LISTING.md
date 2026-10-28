# ScamShield — Chrome Web Store listing pack

Copy-paste source for the store listing. Image assets live in `Promo_Images/`
(all dimensions verified). Update this file if the listing copy changes.

---

## Graphic assets (`Promo_Images/`)

| File | Size | Purpose |
|---|---|---|
| `screenshot-1-scan-1280x800.png` | 1280×800 | Screenshot 1 — scan verdict |
| `screenshot-2-history-1280x800.png` | 1280×800 | Screenshot 2 — security timeline |
| `screenshot-3-privacy-1280x800.png` | 1280×800 | Screenshot 3 — privacy explainer |
| `screenshot-ai-analysis-summary.png` | popup crop | AI analysis summary (confidence + rationale) |
| `screenshot-ai-indicators.png` | popup crop | AI finding cards (HTTP login, urgency, fake warnings) |
| `screenshot-rule-evidence.png` | popup crop | Rule evidence (unknown scripts, credential pressure) |
| `screenshot-critical-rule-findings.png` | popup crop | Critical rules (fake warning, OTP, fake KYC) |
| `screenshot-risk-factor-cards.png` | popup crop | Risk factors (password/urgency/giveaway rules) |
| `screenshot-form-submit-warning.png` | page crop | "Do not fill this form" submit interstitial |
| `screenshot-block-page.png` | page crop | Full-tab block page (worst cases only) |
| `promo-small-440x280.png` | 440×280 | Small promo tile (**required**) |
| `promo-large-920x680.png` | 920×680 | Large promo tile (recommended) |
| `promo-marquee-1400x560.png` | 1400×560 | Marquee banner (optional) |

Store icon (128×128): reuse `extension/public/icons/icon128.png`.

---

## Category & language

- **Category:** Privacy & Security (fallback: Productivity)
- **Language:** English (en)
- **Pricing:** Free
- **Distribution:** Public, all regions

---

## Summary (max 132 characters)

```
Scam & phishing detector: instant risk verdicts for every site. Rule-based, AI-assisted, privacy-first. Free & open source.
```

---

## Detailed description

```
Know before you trust.

ScamShield analyzes the website you're visiting and gives you a clear,
honest risk verdict — Protected, Be careful, or Stop — before you type a
password, card number, or OTP into it.

HOW IT WORKS
• Deterministic rule engine checks the URL, domain identity, page structure,
  forms, redirects, and domain age — always on, fully offline-capable.
• Threat intelligence: Google Safe Browsing, the OpenPhish phishing feed,
  and a curated lookalike-domain list.
• AI second opinion: when local evidence matches its AI-trigger rules, a
  Groq AI analyst reviews sanitized security signals only. AI can never
  overrule a confirmed threat match.
• Every finding explains WHY it affected the verdict — no black boxes.

AUTOMATIC PROTECTION
• Auto-scan flags risky sites as you browse, warns via side panel and badge,
  and blocks form submissions on dangerous pages.

PRIVACY-FIRST — BY ARCHITECTURE, NOT PROMISE
• Scan history and settings stay on your device only (last 50 scans).
• Passwords, OTPs, card numbers, cookies, and form contents are structurally
  unrepresentable in what ScamShield collects — never stored, never sent.
• The page URL and domain are sent to the ScamShield backend for threat
  lookup. When local evidence warrants AI, sanitized metadata is sent to
  Groq. No analytics. No tracking. No ads.

FREE & OPEN SOURCE
• Every line of code is public and auditable. No accounts, no paywalls.

SUPPORT
• Questions or false positives? Email ahasasjain053@gmail.com
```

---

## Permission justifications (one line each)

- **activeTab** — Read the current tab's URL when you click Scan or when
  auto-scan runs; the scan target.
- **scripting** — Inject the page-signal collector on demand during a scan
  (form structure, wording patterns, redirect metadata — never field contents).
- **storage** — Keep settings and the last 50 scan results on this device only.
- **sidePanel** — Open the warning panel when auto-scan flags a risky site.
- **Host permissions (http/https)** — Collect page metadata for analysis and
  communicate with the ScamShield analysis backend.
- **webNavigation (optional)** — Measure redirect chains for the scan.
  Everything works without it; coverage is reported honestly either way.

---

## Privacy practices tab (data-usage disclosure)

- **Data collected for the single purpose (scam detection):** the visited
  page's URL/hostname, structural page signals (form types present, wording
  counts — never field contents), redirect metadata, and domain-age data.
- **Never collected, never transmitted:** passwords, OTPs/PINs, card numbers,
  CVVs, UPI identifiers, cookies/session tokens, form field contents of any
  kind, full page text.
- **Where it goes:** scan history and settings stay in the browser profile
  only (50-entry cap, user-clearable). The page URL and domain are sent to the
  first-party ScamShield backend for threat lookup. When local evidence
  warrants AI, sanitized metadata is sent to Groq.
- **Subprocessors:** Google Safe Browsing (page URL for threat lookup), Groq
  (sanitized metadata for AI), RDAP.org (domain for registration age), and
  Render (backend hosting).
- **Retention:** no persistent scan database; short-lived in-memory threat
  caches only. Local history is capped and deletable at any time.
- **No sale / no unrelated use:** data is not sold, not used for advertising,
  and not used for creditworthiness or lending.

---

## Privacy policy URL

The policy is hosted publicly at:

```
https://github.com/Ahasasjain/Scam-Shield/blob/main/PRIVACY.md
```

Keep it in sync with the disclosure above.

---

## Support contact

- **Email:** ahasasjain053@gmail.com (displayed publicly on the listing)

---

## Post-publish steps (do not skip)

1. Create/publish the listing → the Store assigns the permanent extension ID.
2. Set
   `ALLOWED_EXTENSION_ORIGINS=chrome-extension://<that-id>,chrome-extension://<unpacked-id>`
   on the backend and redeploy.
3. Install the store build and verify `/api/threat-lookup` and `/api/analyze`
   work without 403/CORS errors.

The backend URL is already baked into the production build; no rebuild is
needed just because the store assigned a new ID.
