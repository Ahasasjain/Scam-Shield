# ScamShield — Deployment Guide

Complete instructions for deploying the ScamShield backend (Node.js + Express) and building/publishing the Chrome extension.

---

## Architecture overview

```
Chrome Extension (extension/dist)          Backend (server/)
├── Rule engine (local, always on)   ───►  /api/threat-lookup
├── Bundled local threat feed              ├── OpenPhish feed (auto-refreshed)
└── Optional AI analysis            ───►  /api/analyze
                                          └── OpenAI API (key stays here)
```

The extension works without the backend. With it, you get:
- **OpenPhish feed** — millions of live phishing URLs, refreshed every 30 minutes
- **AI analysis** — GPT-based signal correlation with your key kept server-side

---

## Part 1 — Deploy the backend

### Option A: Render (easiest, free tier)

1. Push this repo to GitHub (done: `github.com/Ahasasjain/Scam-Shield`).
2. Go to [dashboard.render.com](https://dashboard.render.com) → **New → Web Service**.
3. Connect your GitHub repo.
4. Settings:
   - **Root directory**: `server`
   - **Build command**: `pnpm install && pnpm build`
   - **Start command**: `pnpm start`
   - **Instance type**: Free
5. Environment variables:
   ```
   NODE_ENV=production
   AI_API_KEY=sk-proj-...        # your OpenAI key
   AI_MODEL=gpt-4o-mini
   ALLOWED_EXTENSION_ORIGINS=chrome-extension://<YOUR_EXTENSION_ID>
   RATE_LIMIT_MAX=60
   RATE_LIMIT_WINDOW_MINUTES=15
   THREAT_FEED_URL=https://openphish.com/feed.txt
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

### Option C: Docker (any VPS)

Create `server/Dockerfile`:

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN npm i express@4 helmet cors express-rate-limit dotenv pino openai zod @scamshield/shared
EXPOSE 8787
CMD ["node", "dist/index.js"]
```

```bash
docker build -t scamshield-api ./server
docker run -d -p 8787:8787 \
  -e NODE_ENV=production \
  -e AI_API_KEY=sk-proj-... \
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

| Env var | Default | Notes |
|---|---|---|
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
#    Visit google.com → 🛡️ Verified safe
#    Visit any paypa1.com-style domain → 🛑 Dangerous
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

| Symptom | Fix |
|---|---|
| "Threat intelligence unavailable" persists | Backend down or URL wrong — check `/api/health`; check browser console of the service worker |
| AI card says unavailable | `AI_API_KEY` missing/invalid on backend; check backend logs |
| CORS errors in service worker console | `ALLOWED_EXTENSION_ORIGINS` doesn't match your extension ID |
| Feed empty (`entryCount: 0`) | Network egress blocked from host, or OpenPhish rate-limited — logs show `threat feed refresh failed` |
| Auto-scan not firing | Reload extension after update; settings migration applies once per version bump |
