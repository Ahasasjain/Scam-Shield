# ScamShield — Deployment Guide

How to ship both halves of ScamShield. Everything that runs on a server is a
Docker image built by GitHub Actions; the extension is packaged by the same
pipeline.

| Piece | What it is | How it ships |
| --- | --- | --- |
| **Backend** (`server/`) | Node 20 + Express API — Google Safe Browsing, OpenPhish feed, optional Groq AI | **Docker image** (`server/Dockerfile`), built by GitHub Actions and run on Render / AWS EC2 / any Docker host |
| **Extension** (`extension/`) | Chrome MV3 extension — React popup + side panel ("frontend") | Built and zipped by GitHub Actions, then installed via the Chrome Web Store or `chrome://extensions` |

> **Why the extension has no container.** Its UI is not a website: it runs inside
> Chrome and calls `chrome.*` APIs, so there is nothing to host and nothing for a
> web server to serve. "Deploying" the extension means *packaging* `extension/dist`
> into a zip and publishing it — the `release-extension.yml` workflow does exactly
> that, and can push it to the Chrome Web Store for you (Part 2).

---

## 0. The GitHub Actions pipeline

| Workflow | Trigger | What runs |
| --- | --- | --- |
| `ci.yml` | pull request to `main` (or manual) | install → build → lint → typecheck → test, plus a build-only `docker build` of `server/Dockerfile` |
| `deploy-server.yml` | push to `main` touching `server/**`, `shared/**`, the lockfile or compose files (or manual) | verify → build & push `ghcr.io/<owner>/<repo>/scamshield-api:latest` (+ `:sha-…`) → trigger Render and/or deploy over SSH to EC2 |
| `release-extension.yml` | tag `v*` (or manual) | build with the backend URL baked in → test → zip → GitHub release asset → optional Chrome Web Store upload |

Both deploy targets are **opt-in**: a target whose secrets are not configured
prints a GitHub notice and skips instead of failing, so you can start with Render
today and add AWS later without editing any workflow file.

### Secrets the workflows read

Settings → Secrets and variables → Actions → **Secrets** (all optional):

| Secret | Used by | Where to get it |
| --- | --- | --- |
| `RENDER_DEPLOY_HOOK` | `deploy-server` | Render → your service → Settings → Deploy Hook |
| `EC2_HOST` | `deploy-server` | Public IP / Elastic IP of the instance |
| `EC2_USER` | `deploy-server` | `ec2-user` (AL2023) or `ubuntu` (Ubuntu AMI) |
| `EC2_SSH_KEY` | `deploy-server` | Contents of the `.pem` key pair |
| `GHCR_USER`, `GHCR_TOKEN` | `deploy-server` | Only if the GHCR package stays private — PAT with `read:packages` |
| `CWS_EXTENSION_ID`, `CWS_PUBLISHER_ID`, `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN` | `release-extension` | Part 2, "Automated Web Store publishing" |

Settings → Secrets and variables → Actions → **Variables**:

| Variable | Used by | Value |
| --- | --- | --- |
| `SCAMSHIELD_API_URL` | `release-extension` | Public backend URL baked into the bundle, e.g. `https://scamshield-api.onrender.com` |
| `EC2_APP_DIR` | `deploy-server` | Repo checkout on the server; defaults to `~/scamshield` |

---

## Part 1 — Deploy the backend (Docker)

### Which host?

| Option | Cost | Effort | Notes |
| --- | --- | --- | --- |
| **Render free** ⭐ | **$0** | lowest | Free instance (0.1 CPU / 512 MB), Docker builds, managed TLS. Spins down after 15 min idle — the next request takes ~1 min to wake it. 750 free instance-hours/month |
| **AWS EC2 + GHCR** | **$0 while credits last, then ≈ $10–12/mo** | medium | Accounts created **after 15 Jul 2025**: up to **$200 credits, Free plan ends after 6 months** (the account closes unless converted to Paid). Accounts created before that keep the legacy 12-month t2/t3.micro allowance. A public IPv4 adds ≈ $3.60/mo. Good for learning AWS, not for staying free |
| **Any Docker VPS** (Hetzner, DigitalOcean, Lightsail, …) | ≈ $4–6/mo | low | `docker compose up -d --build` + the bundled Caddy profile; full control, no cold starts |
| **Railway** | trial credits, then usage-based | low | Repo-connect deploy; set the Dockerfile path in Settings → Build |

Free-tier terms change — check the provider's pricing page before relying on it.

### Option A — Render (free, recommended, Docker)

1. Push this repo to GitHub.
2. [dashboard.render.com](https://dashboard.render.com) → **New → Blueprint** → pick the repo.
   `render.yaml` wires everything: Dockerfile `./server/Dockerfile`, build context
   `.` (repo root — required, because the backend depends on the
   `@scamshield/shared` workspace package via `workspace:*`, which only resolves
   from the root), `plan: free`, health check `/api/health`.
3. Render prompts for the values marked `sync: false` in `render.yaml`:
   `GROQ_API_KEY`, `GOOGLE_SAFEBROWSING_API_KEY`, `ALLOWED_EXTENSION_ORIGINS`
   (see the env table below). **Do not set `PORT`** — Render injects it.
4. Deploy. You get `https://scamshield-api-xxxx.onrender.com`; check `/api/health`.
5. **Wire the pipeline** (optional but recommended): Render → your service →
   Settings → **Deploy Hook** → copy the URL into the `RENDER_DEPLOY_HOOK` secret.
   From then on, every push to `main` that passes lint/typecheck/tests redeploys
   the API, and nothing ships while the pipeline is red. `render.yaml` sets
   `autoDeployTrigger: "off"` on purpose to keep that single deploy path.

   Alternative: skip the hook and let Render auto-deploy on every push
   (Settings → Build & Deploy → Auto-Deploy) — simpler, but a red build can
   reach production.
6. Free-tier behaviour to expect: after 15 min without traffic the service spins
   down; the next request wakes it in about a minute. A cold-starting backend is
   reported by the extension as *threat intelligence unavailable* — it does
   **not** claim the site is clean, and the local rule engine keeps working.

No blueprint? New → **Web Service** → Language **Docker**, Dockerfile Path
`./server/Dockerfile`, Docker Build Context Directory `.`, health check
`/api/health`, instance type **Free**, then add the same env vars.

### Option B — AWS EC2 (with the GHCR image built by Actions)

What you get: GitHub Actions builds `ghcr.io/<owner>/<repo>/scamshield-api` and
SSHes into an instance that pulls the image with `docker compose`. No AWS API
calls, no ECR, no OIDC — just an SSH key.

1. **Account.** New accounts are on the credit-based Free plan (up to $200,
   6 months, then the account closes unless you convert to Paid); accounts
   created before 15 Jul 2025 keep the legacy 12-month `t3.micro` allowance.
2. **Launch the instance.** EC2 → Launch instance:
   - AMI **Amazon Linux 2023**, type **t3.micro** (free-tier eligible where applicable), 8 GB gp3
   - Security group inbound: **22** (your IP only), **80**, **443**; outbound: all
   - **Advanced details → User data**: paste [`deploy/ec2-user-data.sh`](../deploy/ec2-user-data.sh)
     (installs Docker + Compose and clones the repo to `~/scamshield`)
3. **Configure the server**:
   ```bash
   ssh ec2-user@<public-ip>
   cd ~/scamshield
   cp server/.env.example server/.env
   nano server/.env          # GROQ_API_KEY, GOOGLE_SAFEBROWSING_API_KEY, ALLOWED_EXTENSION_ORIGINS
   docker compose up -d
   curl -s http://localhost:8787/api/health
   ```
4. **Add GitHub secrets**: `EC2_HOST` (Elastic IP recommended), `EC2_USER=ec2-user`,
   `EC2_SSH_KEY` (the `.pem` contents). Push to `main` → the workflow pushes the
   image to GHCR and runs `docker compose pull && up -d` on the instance, then
   checks `/api/health`.

   > **GHCR packages are private by default**, even for public repos. Either
   > change visibility (repo → Packages → the package → Package settings →
   > Danger Zone → Change visibility → Public) so the server can pull
   > anonymously — the repo is public anyway — or keep it private and set
   > `GHCR_USER` + `GHCR_TOKEN` (PAT with `read:packages`).
5. **HTTPS (recommended before shipping)**: point a DNS A record at the Elastic
   IP, then on the instance:
   ```bash
   echo "DOMAIN=api.example.com" >> ~/scamshield/.env
   docker compose --profile edge up -d      # Caddy obtains a Let's Encrypt cert
   ```
   Close port 8787 in the security group, and use `https://api.example.com` as
   the `SCAMSHIELD_API_URL` for the extension build.
6. Repo changes to `docker-compose.yml`/`Caddyfile` arrive via `git pull` on the
   instance (the bootstrap clones a public repo). Private repo? Add a read-only
   deploy key to the instance, or `scp` the files manually.

Prefer ECR over GHCR? Swap the login/push steps in `deploy-server.yml` for
`aws-actions/configure-aws-credentials` + `aws-actions/amazon-ecr-login` and give
the instance an IAM role with ECR read access. Everything else stays the same.

### Option C — any Docker host (compose, no CI required)

```bash
git clone <your-repo> && cd <repo>        # or just copy docker-compose.yml
cp server/.env.example server/.env        # fill in the keys
docker compose up -d --build              # API on :8787
curl -s http://localhost:8787/api/health

# Optional HTTPS (needs a domain pointing here):
echo "DOMAIN=api.example.com" >> .env
docker compose --profile edge up -d       # Caddy: :80/:443 + auto-renewed certs
```

The committed `Dockerfile` is a multi-stage, non-root image with a `HEALTHCHECK`
on `/api/health`. Build it manually if you prefer:

```bash
docker build -f server/Dockerfile -t scamshield-api .
docker run -d -p 8787:8787 --env-file server/.env scamshield-api
```

### Option D — Railway

```bash
npm i -g @railway/cli
railway login
railway init
railway up            # run from the REPO ROOT (workspace resolution)
```

Then in Railway → Settings → Build: set the Dockerfile path to
`server/Dockerfile` and the build context to the repo root. Add the env vars from
the table below; Railway injects `PORT` itself.

### Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `GROQ_API_KEY` | Groq secret key — **server only** | — |
| `GROQ_MODEL` | Groq model | `openai/gpt-oss-120b` |
| `GOOGLE_SAFEBROWSING_API_KEY` (`GCSB_API_KEY` alias) | Google Safe Browsing key — **server only**, highest-signal threat source | — |
| `THREAT_FEED_URL` | Phishing feed URL (one URL per line) | OpenPhish community feed |
| `PORT` | Server port (Render/Railway inject this — don't set it there) | `8787` |
| `NODE_ENV` | `production` rejects requests without an `Origin` header (except `/api/health`) | — |
| `ALLOWED_EXTENSION_ORIGINS` | Comma-separated `chrome-extension://<id>` allowlist | empty = any extension origin (dev only; lock down in production) |
| `RATE_LIMIT_MAX` | Max `/api/analyze` requests per window per IP | `20` |
| `RATE_LIMIT_WINDOW_MINUTES` | Rate-limit window | `15` |
| `THREAT_RATE_LIMIT_MAX` | Max `/api/threat-lookup` requests per window per IP (fires on every scan) | `600` |
| `THREAT_RATE_LIMIT_WINDOW_MINUTES` | Threat-lookup rate-limit window | `15` |
| `LOG_LEVEL` | Pino log level | `info` |

`server/.env.example` is the copy-paste template for all of these. The server
never logs request bodies, and pino redacts secrets.

Build-time variables (extension, via Vite `define` — not runtime settings):

| Variable | Description | Default |
| --- | --- | --- |
| `SCAMSHIELD_API_URL` | Backend URL baked into the bundle | `http://localhost:8787` |
| `SCAMSHIELD_AI_ALWAYS_RUN` | Force an AI call on every scan (dev/test only — costs provider calls) | `false` |

**Never put an API key anywhere in `extension/`.** The key lives exclusively in the server's environment.

### Groq configuration

`/api/analyze` uses Groq only. The server calls Groq's OpenAI-compatible HTTP
endpoint internally; there is no OpenAI, Gemini, Claude, or OpenRouter fallback.

```env
GROQ_API_KEY=gsk_...
GROQ_MODEL=openai/gpt-oss-120b
```

AI runs only when local evidence is meaningful. HTTPS, an ordinary
login/payment form, a long URL, an uncommon TLD, or a brand word alone does not
trigger AI. If Groq fails, ScamShield returns local/threat-intelligence evidence
in `Non-AI` mode with a coverage limitation — it never silently downgrades a
deterministic finding.

### Post-deploy: lock CORS

`NODE_ENV=production` rejects requests with no `Origin` header (except
`/api/health`). With no allowlist set, **any** `chrome-extension://` origin is
accepted — fine for development, wrong for production:

1. Load the unpacked extension (`chrome://extensions` → Load unpacked → `extension/dist`).
2. Copy the **ID** shown on the extension card.
3. Set `ALLOWED_EXTENSION_ORIGINS=chrome-extension://<that-id>` in your host's env and redeploy.
4. Rebuild the extension with the backend URL baked in (Part 2).

---

## Part 2 — Build & release the extension

### Development build

```bash
pnpm install
pnpm dev:extension        # vite build --watch (not a dev server)
```

Load: `chrome://extensions` → Developer mode → **Load unpacked** → select
`extension/dist`. There is no HMR — click **Reload** on the extension card after
each rebuild.

### Production build (bakes in the backend URL)

The API URL is compiled into the bundle — users never configure anything:

```bash
# PowerShell
$env:SCAMSHIELD_API_URL = "https://scamshield-api-xxxx.onrender.com"
pnpm --filter @scamshield/extension build

# Bash
SCAMSHIELD_API_URL="https://scamshield-api-xxxx.onrender.com" pnpm --filter @scamshield/extension build
```

Verify the value landed in the bundle (it lives in the shared storage chunk, not
`background.js`):

```powershell
Get-ChildItem -Recurse extension/dist -Include *.js | Select-String -Pattern "your-domain.example" -List
```

### Release pipeline (tag → zip → release asset)

1. Bump `version` in `extension/public/manifest.json` **and** `extension/package.json`.
2. Commit, then tag: `git tag v1.0.1 && git push origin v1.0.1`.
3. `release-extension.yml` builds with `SCAMSHIELD_API_URL`
   (repository **variable**, or the manual `api_url` input), asserts the URL is
   present in `extension/dist`, runs the test suite, and attaches
   `scamshield-extension.zip` to a GitHub release. The zip is also uploaded as a
   workflow artifact.

### Automated Web Store publishing (optional)

Add five secrets and every tag push uploads and publishes automatically:

| Secret | Where to get it |
| --- | --- |
| `CWS_EXTENSION_ID` | `chrome://extensions` → the ID shown for the installed extension |
| `CWS_PUBLISHER_ID` | Developer Dashboard → **Publisher → Settings** |
| `CWS_CLIENT_ID` / `CWS_CLIENT_SECRET` | Google Cloud Console → new project → enable **Chrome Web Store API** → OAuth consent screen (External, add yourself as test user) → Credentials → Create OAuth client ID → **Desktop app** |
| `CWS_REFRESH_TOKEN` | [OAuth 2.0 Playground](https://developers.google.com/oauthplayground) → gear icon → *Use your own OAuth credentials* (paste client id/secret) → scope `https://www.googleapis.com/auth/chromewebstore` → Authorize → exchange the code for tokens → copy the **refresh token** |

Notes:

- Google Cloud OAuth clients used by a *published* extension must be in
  "In production" status, or the API calls fail; the consent screen can stay
  unverified for personal use.
- The API cannot create a **new** listing — upload the first version manually
  through the [developer dashboard](https://chrome.google.com/webstore/devconsole)
  ($5 one-time developer fee), then let the pipeline handle updates.
- `publish: true` requests a store review of the uploaded version; updates may
  take a few hours to a few days to go live.

### Store submission details

Zip requirement: `manifest.json` must be at the archive **root** — the workflow's
`cd extension/dist && zip -r … .` handles that. When submitting manually:

```powershell
Compress-Archive -Path extension\dist\* -DestinationPath scamshield-v1.0.1.zip
```

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
| --- | --- | --- |
| `THREAT_FEED_URL` | `https://openphish.com/feed.txt` | Swap for a premium feed URL |

**Licensing:** OpenPhish Community is free for **non-commercial use only**. For a commercial product, either buy an OpenPhish Premium license or switch `THREAT_FEED_URL` to a licensed provider (PhishTank requires attribution; URLhaus is MPL-2.0 and commercial-friendly).

To add more feeds, edit `server/src/services/openPhishFeed.ts` — `refreshFeed()` accepts any plain-text URL list (one URL per line). The feed status is logged at boot and reported per lookup; an empty feed is never read as "checked, nothing found".

---

## Part 4 — Verification checklist

```bash
# 1. Health (exempt from the origin check and rate limiting)
curl https://<your-url>/api/health
# → {"ok":true,...}

# 2. Threat lookup. In production (NODE_ENV=production) an Origin header is
#    required — without it the server answers 403 by design.
curl -X POST https://<your-url>/api/threat-lookup \
  -H "Content-Type: application/json" \
  -H "Origin: chrome-extension://<your-extension-id>" \
  -d '{"url":"https://example.com","registrableDomain":"example.com"}'
# → {"available":true,"matched":false,"status":"NO_KNOWN_THREAT","safeBrowsingStatus":"NO_KNOWN_THREAT"}
#   (available:false + status:"UNAVAILABLE" means a provider is down or
#    unconfigured — not that the site is safe)

# 3. Docker (self-hosted / EC2)
docker compose ps            # api = healthy
docker compose logs -f api   # pino JSON logs

# 4. Pipeline
#    Actions → Deploy server → both "Verify" and the image/deploy jobs green
#    Actions → Release extension → artifact scamshield-extension.zip present

# 5. Extension end-to-end
#    Visit google.com → "No known threats found" verdict
#    Visit any paypa1.com-style domain → "Likely dangerous website" verdict
#    Auto-scan warns via the side panel/badge on suspicious pages
```

---

## Part 5 — Updating

| Change | What happens |
| --- | --- |
| Backend code (`server/`, `shared/`) pushed to `main` | `deploy-server.yml` verifies, pushes a new image, redeploys Render (hook) and/or EC2 (SSH) |
| `docker-compose.yml` / `Caddyfile` changed | Run `git pull && docker compose up -d` on the box (or re-run the bootstrap on a fresh instance) |
| Extension changed | Bump `version` in `extension/public/manifest.json` + `extension/package.json`, push, tag `v…` → release asset + optional store publish |
| Secrets rotated | Update them in the host's env (Render dashboard / `server/.env` + `docker compose up -d`) and in GitHub secrets for CI |

Extension version bumps must match between `manifest.json` and `package.json` — the Web Store rejects a re-used version number.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "Threat intelligence unavailable" persists | Backend down or URL wrong — check `/api/health` and the service-worker console. After a Render cold start, retry once the service wakes |
| AI card says unavailable | `GROQ_API_KEY` missing/invalid, rate-limited, timed out, or unavailable; local analysis remains available |
| CORS errors in the service-worker console | `ALLOWED_EXTENSION_ORIGINS` doesn't match your extension ID (production rejects unlisted origins) |
| `403 unauthorized` from curl | Expected in production without an `Origin` header — add `-H "Origin: chrome-extension://<id>"` |
| Feed empty (`entryCount: 0`) | Network egress blocked from the host, or OpenPhish rate-limited — logs show `threat feed refresh failed` |
| Auto-scan not firing | Reload the extension after an update; settings migration applies once per version bump |
| `deploy-server` printed "skipping Render" / "skipping AWS" | That target's secrets are absent by design — see §0 |
| `docker compose` says `env file server/.env not found` | `cp server/.env.example server/.env` and fill it in |
| EC2 deploy fails with `pull access denied` | GHCR package is private — make it public or set `GHCR_USER`/`GHCR_TOKEN` |
| EC2 deploy fails on `docker: command not found` | The user-data bootstrap didn't finish or Docker was never installed — re-run `deploy/ec2-user-data.sh` as root |
| Render deploy fails on `workspace:*` resolution | Build context isn't the repo root — keep Dockerfile Path `./server/Dockerfile` + Context `.` |
| Caddy keeps restarting | `DOMAIN` is unset or DNS doesn't point here — check `docker compose logs caddy` |
| Extension can't reach the API after deploy | Rebuild/re-release the extension: the URL is baked in at build time, changing it requires a new build |
