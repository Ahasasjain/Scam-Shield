# ScamShield — Deployment Guide

Complete instructions for deploying the ScamShield backend (Node.js + Express) and building/publishing the Chrome extension.

---

## Architecture overview

```
Chrome Extension (extension/dist)          Backend (server/)
├── Rule engine (local, always on)   ───►  /api/threat-lookup
├── Bundled local threat feed              ├── OpenPhish feed (auto-refreshed)
└── Optional AI analysis            ───►  /api/analyze
                                          └── Groq API (server-side key)
```

The extension works without the backend. With it, you get:

- **OpenPhish feed** — millions of live phishing URLs, refreshed every 30 minutes
- **AI analysis** — optional Groq enrichment using `openai/gpt-oss-120b`; the key stays server-side and local detection never depends on AI

---

## Part 1 — Deploy the backend

### Option A: Render (easiest, free tier)

1. Push this repo to GitHub (done: `github.com/Ahasasjain/Scam-Shield`).
2. Go to [dashboard.render.com](https://dashboard.render.com) → **New → Web Service**.
3. Connect your GitHub repo.
4. Settings (**Root directory must be the repo root**, not `server/` — the
   backend depends on the `@scamshield/shared` workspace package, and the
   `workspace:*` protocol only resolves from the repo root):
   - **Root directory**: `.` (repo root — leave blank/default)
   - **Build command**: `corepack enable && pnpm install --frozen-lockfile && pnpm --filter @scamshield/server build`
   - **Start command**: `pnpm --filter @scamshield/server start`
   - **Instance type**: Free
5. Environment variables (Render provides `PORT` automatically — do not set it):
   ```
   NODE_ENV=production
   GROQ_API_KEY=gsk_...                      # server-side only
   GROQ_MODEL=openai/gpt-oss-120b
   GOOGLE_SAFEBROWSING_API_KEY=...           # strongly recommended
   ALLOWED_EXTENSION_ORIGINS=chrome-extension://<YOUR_EXTENSION_ID>
   RATE_LIMIT_MAX=60
   RATE_LIMIT_WINDOW_MINUTES=15
   THREAT_RATE_LIMIT_MAX=600
   THREAT_RATE_LIMIT_WINDOW_MINUTES=15
   THREAT_FEED_URL=https://openphish.com/feed.txt
   LOG_LEVEL=info
   ```
6. Click **Create Web Service**. You'll get a URL like `https://scamshield-xxxx.onrender.com`.
7. Verify: open `https://<your-url>/api/health` → should return `{"ok":true,...}`.

> **Note:** free tier sleeps after 15 min idle; first request takes ~30 s to wake. Paid tier ($7/mo) removes this.

### Option B: Railway

```bash
npm i -g @railway/cli
railway login
cd server
railway init
railway up
# Then set env vars in the Railway dashboard (same list as above).
```

### Groq configuration

The `/api/analyze` endpoint uses Groq only. The server calls Groq's OpenAI-compatible HTTP endpoint internally, but there is no OpenAI, Gemini, Claude, or OpenRouter fallback.

```env
GROQ_API_KEY=gsk_...
GROQ_MODEL=openai/gpt-oss-120b
```

Groq calls are made only when local evidence is meaningful. HTTPS, an ordinary login/payment form, a long URL, an uncommon TLD, or a brand word alone does not trigger AI.

If Groq fails, ScamShield returns local/threat-intelligence evidence in `Non-AI` mode with a coverage limitation. It makes no provider fallback request.

---

### Option C: Docker (any VPS)

A production `server/Dockerfile` is committed (multi-stage, non-root user,
healthcheck). Build from the **repo root** so the workspace resolves:

```bash
docker build -f server/Dockerfile -t scamshield-api .
docker run -d -p 8787:8787 \
  -e NODE_ENV=production \
  -e GROQ_API_KEY=gsk_... \
  -e GROQ_MODEL=openai/gpt-oss-120b \
  -e GOOGLE_SAFEBROWSING_API_KEY=... \
  -e ALLOWED_EXTENSION_ORIGINS="chrome-extension://<ID>" \
  scamshield-api
```

Put nginx/Caddy in front for HTTPS.

### Post-deploy: lock CORS

1. Load the unpacked extension (`chrome://extensions` → Load unpacked → `extension/dist`).
2. Copy the **ID** shown on the extension card.
3. Set `ALLOWED_EXTENSION_ORIGINS=chrome-extension://<that-id>` in your backend's env and redeploy.
4. Rebuild the extension with the backend URL baked in (see below).

---

## Part 2 — Build & publish the extension

### Development build

```bash
pnpm install
pnpm --filter @scamshield/extension build
```

Load: `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/dist`.

### Production build (bakes in your backend URL)

The API URL is compiled into the bundle — users never configure anything:

```bash
# PowerShell
$env:SCAMSHIELD_API_URL = "https://scamshield-xxxx.onrender.com"
pnpm --filter @scamshield/extension build

# Bash
SCAMSHIELD_API_URL="https://scamshield-xxxx.onrender.com" pnpm --filter @scamshield/extension build
```

Verify it's baked in:

```bash
Select-String -Path extension\dist\background.js -Pattern "onrender.com"
```

### Package for Chrome Web Store

```powershell
Compress-Archive -Path extension\dist\* -DestinationPath scamshield-v1.0.0.zip
```

Submit at [chrome.google.com/webstore/devconsole](https://chrome.google.com/webstore/devconsole) ($5 one-time fee):

- Upload the zip
- Privacy policy URL: `https://github.com/Ahasasjain/Scam-Shield/blob/main/PRIVACY.md`
- Permissions justification:
  - `activeTab` — read current tab URL when user/auto scan runs
  - `scripting` — inject page-signal collector on demand
  - `storage` — local settings/history
  - `sidePanel` — warning panel
- Single purpose: "Detect scam and phishing websites"

Review typically takes 1–3 days for low-permission extensions.

---

## Part 3 — Threat feed configuration

The backend auto-downloads the OpenPhish Community Feed every 30 minutes.

| Env var           | Default                          | Notes                       |
| ----------------- | -------------------------------- | --------------------------- |
| `THREAT_FEED_URL` | `https://openphish.com/feed.txt` | Swap for a premium feed URL |

**Licensing:** OpenPhish Community is free for **non-commercial use only**. For a commercial product, either buy an OpenPhish Premium license or switch `THREAT_FEED_URL` to a licensed provider (PhishTank requires attribution; URLhaus is MPL-2.0 and commercial-friendly).

To add more feeds, edit `server/src/services/openPhishFeed.ts` — `refreshFeed()` accepts any plain-text URL list (one URL per line).

---

## Part 4 — Verification checklist

```bash
# 1. Health
curl https://<your-url>/api/health

# 2. Threat lookup (known-bad from feed)
curl -X POST https://<your-url>/api/threat-lookup \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","registrableDomain":"google.com"}'
# → {"available":true,"matched":false}

# 3. Extension end-to-end
#    Visit google.com → "No known threats found" verdict
#    Visit any paypa1.com-style domain → "Likely dangerous website" verdict
#    Auto-scan warns via side panel/badge on suspicious pages
```

---

## Part 5 — Updating

```bash
git pull
pnpm install
pnpm build
# Redeploy backend (Render/Railway auto-deploy on push)
# Repackage + upload extension zip for store updates
```

Extension version bumps go in `extension/public/manifest.json` and `extension/package.json`.

---

## Troubleshooting

| Symptom                                    | Fix                                                                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| "Threat intelligence unavailable" persists | Backend down or URL wrong — check `/api/health`; check browser console of the service worker              |
| AI card says unavailable                   | `GROQ_API_KEY` missing/invalid, rate-limited, timed out, or unavailable; local analysis remains available |
| CORS errors in service worker console      | `ALLOWED_EXTENSION_ORIGINS` doesn't match your extension ID                                               |
| Feed empty (`entryCount: 0`)               | Network egress blocked from host, or OpenPhish rate-limited — logs show `threat feed refresh failed`      |
| Auto-scan not firing                       | Reload extension after update; settings migration applies once per version bump                           |
