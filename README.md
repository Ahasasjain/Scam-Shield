# 🛡️ ScamShield

A production-ready Chrome extension (Manifest V3) that detects potentially fake, malicious, phishing, and scam websites using a **deterministic rule engine**, with **optional Groq AI enrichment** through your own Node.js + Express backend.

> ⚠️ **Important product principle:** ScamShield provides _probabilistic risk indicators_, not guarantees. It never claims a site is "definitely safe" or "definitely a scam".

---

## Features

- 🔍 **Rule-based detection engine** — explainable heuristics covering URL structure, punycode/lookalike domains, brand impersonation (60+ brands with homoglyph similarity), suspicious TLDs, HTTPS usage, page content patterns (login/payment forms, OTP/CVV/UPI collection, urgency language, giveaway scams, fake security warnings, fake KYC), cross-origin form targets, and redirect chains.
- 🧮 **Transparent scoring** — 0–100 score with a "Why this score?" breakdown showing each capped evidence group's contribution, plus an evidence-based verdict (`SAFE` / `LOW_RISK` / `SUSPICIOUS` / `HIGH_RISK` / `DANGEROUS` / `UNKNOWN`). Unknown is never presented as safe.
- 🛡️ **Threat intelligence** — Google Safe Browsing, the auto-refreshed OpenPhish feed, and a bundled offline lookalike-domain list. A confirmed match overrides heuristics; a failed lookup is reported as unavailable, never as "clean".
- 🤖 **Groq AI second opinion** — runs automatically only when local evidence warrants it (never on confirmed threat matches, never able to downgrade a deterministic finding). Only _sanitized security signals_ reach _your_ backend, which holds `GROQ_API_KEY`. Responses are schema-validated before display.
- ⚠️ **Popup-first warnings** — risky sites get an in-page banner (`Back to safety` / `Continue anyway`); sensitive form submissions are intercepted with a `Do not fill this form` interstitial (`Cancel` / `Submit anyway`). Only the worst cases (`DANGEROUS` with score ≤ 15) take over the tab with a full block page.
- 🖥️ **Popup + Side Panel UIs** — modern security-dashboard design with dark/light/system themes. Auto-scan reuses the last verdict instead of rescanning.
- 🕘 **Local scan history** — URL, hostname, score, verdict, top evidence, analysis mode, and time; stored only on-device, capped at 50 entries, clearable anytime.
- ♿ **Accessible** — keyboard navigation, ARIA roles, focus rings, `prefers-reduced-motion` support.

## Architecture

```
scamshield/
├── extension/                  # Chrome MV3 extension (Vite + React + TS + Tailwind v4)
│   ├── public/
│   │   ├── manifest.json       # MV3 manifest — minimal permissions
│   │   └── icons/
│   └── src/
│       ├── background/index.ts # Service worker: scan orchestration, auto-scan,
│       │                       # result cache, full-block gating (score ≤ 15)
│       ├── content/index.ts    # On-demand DOM signal collector + in-page banner
│       │                       # and submit-interstitial popups
│       ├── popup/              # Popup entry (index.html + main.tsx)
│       ├── sidepanel/          # Side panel entry
│       ├── blocked/            # Full-tab block page entry (worst cases only)
│       ├── components/         # SecurityScore, RiskBadge, RiskFactors, AIAnalysis,
│       │                       # VerdictCard, WhyThisScore, Blocked, WebsiteInfo,
│       │                       # ScanProgress, ScanHistory, SettingsPanel,
│       │                       # PrivacyExplainer, RecommendationCard, ErrorState…
│       ├── services/
│       │   ├── scanner/        # ruleEngine, urlAnalyzer, pageAnalyzer,
│       │   │                   # redirectAnalyzer, reputationAnalyzer,
│       │   │                   # threatIntelligenceAnalyzer, correlationEngine,
│       │   │                   # evidenceBuilder, aiDecision
│       │   ├── ai/             # AIAnalyzer interface + HttpAIAnalyzer
│       │   └── api/            # Typed messaging client
│       ├── hooks/              # useExtensionState
│       ├── utils/              # url, scoring, storage, validation, logger,
│       │                       # domainIdentity (brand registry + similarity)
│       └── styles/global.css   # Tailwind v4 theme tokens
├── server/                     # Node.js + Express + TypeScript API
│   └── src/
│       ├── index.ts            # App bootstrap: helmet, CORS, rate limit, routes
│       ├── routes/             # analyze.ts, threatLookup.ts, health.ts
│       ├── middleware/         # errorHandler, rateLimit, originCheck
│       ├── services/           # groqAnalyzer.ts (strict JSON + Zod validation),
│       │                       # safeBrowsing.ts, openPhishFeed.ts
│       └── lib/logger.ts       # pino structured logging with redaction
├── shared/                     # Shared types + Zod schemas (single source of truth)
├── pnpm-workspace.yaml
├── .env.example
└── README.md
```

### Data flow

```
Popup/Side Panel ──SCAN_WEBSITE──▶ Background service worker
                                        │
                        validate URL ──▶ inject content.js on demand
                                        │   (+ redirect signals if permitted)
                                        │
                        threat intel ──▶ POST /api/threat-lookup (Express)
                                        │   (Safe Browsing + OpenPhish + local feed)
                                        │
                              run rule engine (deterministic)
                                        │
              meaningful evidence? ──▶ POST /api/analyze (Express)
                                        │                    │
                                        │              Groq (JSON mode)
                                        │                    │
                                        ◀── Zod-validated ──┘
                                        │
              combine + score + verdict ──▶ in-page banner popup,
                  history write             side-panel warning, or
                                            full block (DANGEROUS, score ≤ 15)
```

## Quick start

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9 (`corepack enable`)

### Install & build

```bash
pnpm install
pnpm build          # builds extension/ and server/
```

### Load the extension into Chrome

1. Run `pnpm dev:extension` (watch build) or `pnpm --filter @scamshield/extension build`.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** and select the `extension/dist` folder.
5. Pin ScamShield to the toolbar and click the shield icon on any website.

### Run the AI backend (recommended)

```bash
cp server/.env.example server/.env
# Edit server/.env — set GROQ_API_KEY=gsk_... (never commit it!)
# For real threat coverage also set GOOGLE_SAFEBROWSING_API_KEY=...

pnpm dev:server     # http://localhost:8787
```

No settings to change in the extension: the backend URL is baked in at build
time (`SCAMSHIELD_API_URL`, default `http://localhost:8787`), and AI runs
automatically only when local evidence warrants it — there is no AI toggle.
For a production build pointing at your deployed backend, see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

The extension works fully without the backend — threat lookups fall back to
the bundled offline feed, AI reports unavailable, and failures degrade
gracefully ("AI analysis unavailable. Your rule-based security scan is still available.").

## Environment variables

| Variable                    | Description                                              | Default                            |
| --------------------------- | -------------------------------------------------------- | ---------------------------------- |
| `GROQ_API_KEY`              | Groq secret key — **server only**                        | —                                  |
| `GROQ_MODEL`                | Groq model                                               | `openai/gpt-oss-120b`              |
| `GOOGLE_SAFEBROWSING_API_KEY` (`GCSB_API_KEY` alias) | Google Safe Browsing key — **server only**, highest-signal threat source | — |
| `THREAT_FEED_URL`           | Phishing feed URL (one URL per line)                     | OpenPhish community feed           |
| `PORT`                      | Server port                                              | `8787`                             |
| `ALLOWED_EXTENSION_ORIGINS` | Comma-separated `chrome-extension://<id>` allowlist      | empty = any extension origin (dev only; lock down in production) |
| `RATE_LIMIT_MAX`            | Max `/api/analyze` requests per window per IP            | `20`                               |
| `RATE_LIMIT_WINDOW_MINUTES` | Rate-limit window                                        | `15`                               |
| `THREAT_RATE_LIMIT_MAX`     | Max `/api/threat-lookup` requests per window per IP (fires on every scan) | `600` |
| `THREAT_RATE_LIMIT_WINDOW_MINUTES` | Threat-lookup rate-limit window                   | `15`                               |
| `LOG_LEVEL`                 | Pino log level                                           | `info`                             |

Build-time (extension, via `vite.config.ts` `define` — not runtime settings):

| Variable               | Description                                              | Default                   |
| ---------------------- | -------------------------------------------------------- | ------------------------- |
| `SCAMSHIELD_API_URL`   | Backend URL baked into the bundle                        | `http://localhost:8787`   |
| `SCAMSHIELD_AI_ALWAYS_RUN` | Force an AI call on every scan (dev/test only — costs provider calls) | `false` |

**Never put an API key anywhere in `extension/`.** The key lives exclusively in the server's environment.

## Permissions justification

| Permission                   | Why                                                                                                |
| ---------------------------- | -------------------------------------------------------------------------------------------------- |
| `activeTab`                  | Read the current tab's URL and run the signal collector when the user scans. No broad host access. |
| `scripting`                  | Inject `content.js` on demand during a scan (not on every page).                                   |
| `storage`                    | Persist settings and local scan history on-device.                                                 |
| `sidePanel`                  | Provide the side-panel dashboard.                                                                  |
| `webNavigation` _(optional)_ | Redirect-chain analysis. Not requested unless the user grants it.                                  |

No `<all_urls>`, no background network monitoring, no remote code.

## Privacy

- Settings and history are stored **only** in `chrome.storage.local` on your device.
- Without a backend configured, nothing ever leaves the browser.
- With a backend, the extension sends only minimal sanitized signals: URL/hostname for threat lookup on every scan, and (only when local evidence warrants it) aggregate page-signal counts plus redirect metadata for AI enrichment. Never passwords, cookies, tokens, payment data, or full page contents.
- The backend never logs request bodies; secrets are redacted from logs.

See [PRIVACY.md](PRIVACY.md).

## Development

```bash
pnpm lint           # ESLint (strict type-checked) across workspaces
pnpm typecheck      # tsc --noEmit across workspaces
pnpm test           # Vitest + React Testing Library suites
pnpm --filter @scamshield/extension test:watch
```

Tests cover: every URL heuristic (safe + malicious fixtures), score bands, rule-engine edge cases, AI response validation (valid/hostile payloads), retry/timeout behavior, settings persistence, history capping, and core UI components.

## Production build & deployment

GitHub Actions does the work (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)):

- On pull requests: lint, typecheck, tests, and a `docker build` smoke test.
- On pushes to `main` that touch `server/`/`shared/`: verify → build & push the
  backend Docker image to GHCR → deploy to Render (free tier) and/or over SSH to
  an AWS EC2/VPS host, whichever is configured. Both targets are opt-in via
  secrets; nothing ships while CI is red.
- On `v*` tags: build the extension with the backend URL baked in, zip it,
  attach it to a GitHub release, and optionally publish to the Chrome Web Store.

### Backend (Docker)

```bash
cp server/.env.example server/.env   # fill in the keys
docker compose up -d --build         # API on :8787
# domain + automatic HTTPS:
#   echo "DOMAIN=api.example.com" >> .env && docker compose --profile edge up -d
```

The image is built from `server/Dockerfile` (multi-stage, non-root,
healthcheck). Any Node 20+ host also works without Docker:
`cd server && pnpm install && pnpm build && pnpm start` (honors `PORT`).

Set `NODE_ENV=production`, `GROQ_API_KEY`, `GROQ_MODEL=openai/gpt-oss-120b`, and
`ALLOWED_EXTENSION_ORIGINS=chrome-extension://<your-extension-id>` in production.

### Extension

```bash
SCAMSHIELD_API_URL="https://your-backend.example" \
  pnpm --filter @scamshield/extension build   # outputs extension/dist
cd extension/dist && zip -r ../scamshield.zip .  # manifest.json at zip root
```

## Chrome Web Store checklist

- ✅ Valid MV3 manifest, icons included (16/32/48/128)
- ✅ Minimal permissions, each justified above
- ✅ No secrets in the bundle (key lives server-side only)
- ✅ External service (your backend → Groq, Google Safe Browsing) disclosed in listing + privacy policy
- ✅ No misleading security claims; probabilistic language throughout
- ✅ Works fully without a backend; AI/threat-lookup failures degrade gracefully without breaking the extension
- ✅ CSP-compatible (`script-src 'self'`), no `eval`, no remote code
- ✅ Privacy policy hosted publicly (use PRIVACY.md as the basis)

## Roadmap

VirusTotal · URLScan · enterprise dashboard · exportable PDF reports · QR/email link scanning · additional threat-intel feeds · browser notifications. Already shipped: Google Safe Browsing, OpenPhish feed, RDAP domain-age checks, popup-first warnings with full-tab blocking for the worst cases, and the Groq AI second opinion.

## License

MIT
