# ScamShield — Deployment Guide

Complete instructions for deploying the ScamShield backend (Node.js + Express) and building/publishing the Chrome extension.

---

## Architecture overview

```
Chrome Extension (extension/dist)          Backend (server/)
├── Rule engine (local, always on)   ───►  /api/threat-lookup
├── Bundled local threat feed              ├── OpenPhish feed (auto-refreshed)
└── Optional AI analysis            ───►  /api/analyze
                                          └── Any OpenAI-compatible API
```

The extension works without the backend. With it, you get:

- **OpenPhish feed** — millions of live phishing URLs, refreshed every 30 minutes
- **AI analysis** — provider-agnostic; works with OpenAI, Azure, Groq, Together, OpenRouter, Mistral, Fireworks, Ollama, or any OpenAI-compatible endpoint (key stays server-side)

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
   AI_PROVIDER=openai              # openai | azure | groq | together | openrouter | mistral | fireworks | ollama | custom
   AI_API_KEY=sk-proj-...          # your key for that provider
   AI_MODEL=gpt-4o-mini            # leave blank to use the provider's default
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

### AI provider configuration

The `/api/analyze` endpoint speaks the **OpenAI Chat Completions** protocol, so it works with OpenAI and with any provider that exposes an OpenAI-compatible API. Pick a provider with `AI_PROVIDER` and the server fills in the base URL and default model for you.

| `AI_PROVIDER` | Base URL                                            | Default model                        | API key env          |
| ------------- | --------------------------------------------------- | ------------------------------------ | -------------------- |
| `openai`      | `https://api.openai.com/v1`                         | `gpt-4o-mini`                        | `AI_API_KEY`         |
| `azure`       | _you provide_ (your deployment endpoint)           | _required_ (your deployment name)    | `AI_API_KEY`         |
| `groq`        | `https://api.groq.com/openai/v1`                    | `llama-3.1-70b-versatile`            | `AI_API_KEY`         |
| `together`    | `https://api.together.xyz/v1`                       | `meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo` | `AI_API_KEY` |
| `openrouter`  | `https://openrouter.ai/api/v1`                      | `anthropic/claude-3.5-sonnet`        | `AI_API_KEY`         |
| `mistral`     | `https://api.mistral.ai/v1`                         | `mistral-small-latest`               | `AI_API_KEY`         |
| `fireworks`   | `https://api.fireworks.ai/inference/v1`             | `accounts/fireworks/models/llama-v3p1-70b-instruct` | `AI_API_KEY` |
| `ollama`      | `http://localhost:11434/v1`                         | `llama3.1`                           | `AI_API_KEY=ollama` (any value) |
| `custom`      | _you provide_ (`AI_BASE_URL`)                       | _required_ (`AI_MODEL`)              | `AI_API_KEY`         |

#### Examples

OpenAI (default — what the codebase used to hardcode):
```env
AI_PROVIDER=openai
AI_API_KEY=sk-proj-...
AI_MODEL=gpt-4o-mini
```

Groq (very fast Llama inference, generous free tier):
```env
AI_PROVIDER=groq
AI_API_KEY=gsk_...
AI_MODEL=llama-3.1-70b-versatile
```

OpenRouter (one key, hundreds of models):
```env
AI_PROVIDER=openrouter
AI_API_KEY=sk-or-...
AI_MODEL=anthropic/claude-3.5-sonnet
```

Azure OpenAI (use your full deployment URL as `AI_BASE_URL`):
```env
AI_PROVIDER=azure
AI_API_KEY=<your-azure-key>
AI_BASE_URL=https://<resource>.openai.azure.com/openai/deployments/<deployment>
AI_MODEL=<deployment-name>
```

Ollama (fully local, no key needed):
```env
AI_PROVIDER=ollama
AI_API_KEY=ollama
AI_MODEL=llama3.1
```

LM Studio or any other OpenAI-compatible endpoint (point at it directly):
```env
AI_PROVIDER=custom
AI_BASE_URL=http://localhost:1234/v1
AI_API_KEY=lm-studio
AI_MODEL=local-model
```

> You can also leave `AI_PROVIDER` blank and just set `AI_BASE_URL` + `AI_MODEL` + `AI_API_KEY` — the server treats that the same as `AI_PROVIDER=custom`. This is the easiest way to point at a new provider without editing the registry.

Notes:
- Some providers (Ollama, LM Studio, vLLM, custom proxies) don't support OpenAI's `response_format: { type: "json_object" }`. ScamShield automatically detects those and falls back to free-form completions, then strips any ```` ```json ```` wrappers from the response.
- Model names change often. If a provider ships a new default, just override `AI_MODEL` — you don't need to redeploy code.
- Keep `AI_API_KEY` server-side only. The extension never sees it.

---

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

| Symptom                                    | Fix                                                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| "Threat intelligence unavailable" persists | Backend down or URL wrong — check `/api/health`; check browser console of the service worker         |
| AI card says unavailable                   | `AI_API_KEY` missing/invalid on backend; check backend logs (also verify `AI_PROVIDER` + `AI_BASE_URL` for non-OpenAI providers) |
| CORS errors in service worker console      | `ALLOWED_EXTENSION_ORIGINS` doesn't match your extension ID                                          |
| Feed empty (`entryCount: 0`)               | Network egress blocked from host, or OpenPhish rate-limited — logs show `threat feed refresh failed` |
| Auto-scan not firing                       | Reload extension after update; settings migration applies once per version bump                      |
