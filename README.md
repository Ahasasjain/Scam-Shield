# 🛡️ ScamShield

A production-ready Chrome extension (Manifest V3) that detects potentially fake, malicious, phishing, and scam websites using a **deterministic rule engine**, with **optional AI analysis** powered by the OpenAI API through your own Node.js + Express backend.

> ⚠️ **Important product principle:** ScamShield provides _probabilistic risk indicators_, not guarantees. It never claims a site is "definitely safe" or "definitely a scam".

---

## Features

- 🔍 **Rule-based detection engine** — 15+ explainable heuristics covering URL structure, punycode/lookalike domains, brand impersonation, suspicious TLDs, HTTPS usage, page content patterns (login/payment forms, urgency language, giveaway scams, fake security warnings), and redirects.
- 🧮 **Transparent scoring** — 0–100 score in five bands (Critical / High / Medium / Low / Safe), with a "Why this score?" breakdown showing each category's contribution.
- 🤖 **Optional AI analysis** — off by default. When enabled, only _minimal security signals_ are sent to _your_ backend, which holds the OpenAI key. AI responses are schema-validated (Zod) before display, and can never override deterministic rule findings.
- 🖥️ **Popup + Side Panel UIs** — modern security-dashboard design with dark/light/system themes.
- 🕘 **Local scan history** — hostname, score, risk level, and time; stored only on-device, capped at 50 entries, clearable anytime.
- ♿ **Accessible** — keyboard navigation, ARIA roles, focus rings, `prefers-reduced-motion` support.

## Architecture

```
scamshield/
├── extension/                  # Chrome MV3 extension (Vite + React + TS + Tailwind v4)
│   ├── public/
│   │   ├── manifest.json       # MV3 manifest — minimal permissions
│   │   └── icons/
│   └── src/
│       ├── background/index.ts # Service worker: message router + scan orchestration
│       ├── content/index.ts    # On-demand DOM signal collector
│       ├── popup/              # Popup entry (index.html + main.tsx)
│       ├── sidepanel/          # Side panel entry
│       ├── components/         # SecurityScore, RiskBadge, RiskFactors, AIAnalysis,
│       │                       # AIModeToggle, WebsiteInfo, ScanProgress, ScanHistory,
│       │                       # SettingsPanel, RecommendationCard, ErrorState…
│       ├── services/
│       │   ├── scanner/        # ruleEngine, urlAnalyzer, pageAnalyzer,
│       │   │                   # redirectAnalyzer, reputationAnalyzer
│       │   ├── ai/             # AIAnalyzer interface + HttpAIAnalyzer
│       │   └── api/            # Typed messaging client
│       ├── hooks/              # useSettings, useHistory, useTheme
│       ├── types & utils/      # url, scoring, storage, validation, logger
│       └── styles/global.css   # Tailwind v4 theme tokens
├── server/                     # Node.js + Express + TypeScript API
│   └── src/
│       ├── index.ts            # App bootstrap: helmet, CORS, rate limit, routes
│       ├── routes/             # analyze.ts, health.ts
│       ├── middleware/         # errorHandler, rateLimit, originCheck
│       ├── services/           # openaiAnalyzer.ts (JSON mode + Zod validation)
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
                                        │
                              run rule engine (deterministic)
                                        │
                         AI enabled? ──▶ POST /api/analyze (Express)
                                        │                    │
                                        │              OpenAI (JSON mode)
                                        │                    │
                                        ◀── Zod-validated ──┘
                                        │
                            combine + score ──▶ render result
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

### Run the AI backend (optional)

```bash
cp .env.example server/.env
# Edit server/.env — set AI_API_KEY=sk-... (never commit it!)

pnpm dev:server     # http://localhost:8787
```

Then in the extension: **Settings → enable AI Detection → set AI backend URL** to `http://localhost:8787`.

The extension works fully without the backend — AI is optional by design, and failures degrade gracefully ("AI analysis unavailable. Your rule-based security scan is still available.").

## Environment variables

| Variable                    | Description                                         | Default                            |
| --------------------------- | --------------------------------------------------- | ---------------------------------- |
| `AI_PROVIDER`               | AI provider (`openai`)                              | `openai`                           |
| `AI_API_KEY`                | OpenAI secret key — **server only**                 | —                                  |
| `AI_MODEL`                  | Chat model                                          | `gpt-4o-mini`                      |
| `API_BASE_URL`              | Public base URL of the API                          | `http://localhost:8787`            |
| `PORT`                      | Server port                                         | `8787`                             |
| `ALLOWED_EXTENSION_ORIGINS` | Comma-separated `chrome-extension://<id>` allowlist | empty = any extension origin (dev) |
| `RATE_LIMIT_MAX`            | Max AI requests per window per IP                   | `20`                               |
| `RATE_LIMIT_WINDOW_MINUTES` | Rate-limit window                                   | `15`                               |

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
- With AI **off**, nothing ever leaves the browser.
- With AI **on**, only minimal signals are sent to _your configured backend_: URL structure flags, aggregate page-signal counts, redirect metadata. Never passwords, cookies, tokens, payment data, or full page contents.
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

### Extension

```bash
pnpm --filter @scamshield/extension build   # outputs extension/dist
cd extension && zip -r scamshield.zip dist  # upload to Chrome Web Store
```

### Backend

Any Node 20+ host works (Render, Railway, Fly.io, Docker, VPS):

```bash
cd server
pnpm install && pnpm build && pnpm start    # honors PORT env
```

Set `NODE_ENV=production`, `AI_API_KEY`, and `ALLOWED_EXTENSION_ORIGINS=chrome-extension://<your-extension-id>` in production.

## Chrome Web Store checklist

- ✅ Valid MV3 manifest, icons included (16/32/48/128)
- ✅ Minimal permissions, each justified above
- ✅ No secrets in the bundle (key lives server-side only)
- ✅ External service (your AI backend → OpenAI) disclosed in listing + privacy policy
- ✅ No misleading security claims; probabilistic language throughout
- ✅ Works fully without AI; AI failure doesn't break the extension
- ✅ CSP-compatible (`script-src 'self'`), no `eval`, no remote code
- ✅ Privacy policy hosted publicly (use PRIVACY.md as the basis)

## Roadmap (not in V1)

Google Safe Browsing · VirusTotal · URLScan · WHOIS/domain intelligence · dangerous-site blocking · enterprise dashboard · exportable PDF reports · QR/email link scanning · threat-intel feeds · browser notifications. The `reputationAnalyzer` and `AIAnalyzer` interfaces are the designed integration points.

## License

MIT
