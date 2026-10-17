# AGENTS.md — ScamShield

Chrome MV3 anti-phishing extension (`extension/`) + optional Node/Express AI backend
(`server/`), pnpm workspace with `shared/` holding the cross-package type + Zod contract.

## Commands (verified)

```bash
pnpm install                 # pnpm@9.12.0 via corepack; .npmrc has engine-strict + save-exact
pnpm -r test                 # 17 extension files / 410 tests (jsdom, ~70s) + 5 server files / 43 tests
pnpm -r lint                 # eslint --max-warnings 0
pnpm -r typecheck            # tsc --noEmit  (all 3 packages pass)
pnpm --filter @scamshield/extension dev    # vite build --watch (NOT a dev server)
pnpm --filter @scamshield/server dev      # tsx watch src/index.ts on :8787
```

Single test file: `pnpm --filter @scamshield/extension test src/utils/scoring.test.ts`
(watch mode: `test:watch`). `shared` has no tests (`pnpm -r test` still exits 0).

`extension/package.json` `dev` is `vite build --watch --mode development` — there is no
HMR dev server; you must hit "Reload" in `chrome://extensions` after each rebuild.

### One source of truth for `domainSignals` (was a type error, now fixed)

`ScanContext` exists twice: the Zod-inferred contract in `shared/src/index.ts` (what crosses
the extension↔server boundary) and a hand-written superset in
`extension/src/services/scanner/ruleEngine.ts` (what rules evaluate against). They must stay
assignable to each other.

The original drift: `ruleEngine` declared `domainSignals: { available: boolean; ... }` while
`shared` models it as a **discriminated union** on `available`. A plain `boolean` is not
assignable to `true | false`, so `background/index.ts` and `aiAnalyzer.test.ts` failed to
compile — and since `build` is `tsc --noEmit && vite build`, that blocked the whole bundle.
The fix was to delete the duplicate declaration and have `ruleEngine` import the shared
`DomainSignals` type. Do **not** re-inline a looser shape here, and do **not** add a
`reason`/`source` field outside the union.

`pageAnalyzer` relies on the union's narrowing (`domainSignals?.available === true`), so keep
that form rather than a truthiness check.

## Safe Browsing and "unknown ≠ safe" (spec §2)

`server/src/services/safeBrowsing.ts` returns **one of four explicit states and never `null`**:

| Status | Meaning | `available` |
|---|---|---|
| `KNOWN_MALICIOUS` | provider confirmed a threat | `true` |
| `NO_KNOWN_THREAT` | provider answered, listed nothing — NOT "safe" | `true` |
| `LOOKUP_UNAVAILABLE` | error, timeout, rate limit, malformed, or unconfigured | `false` |
| `UNKNOWN` | well-formed but unrecognised payload | `false` |

This replaced a `null`-on-every-failure design where a 401, a 429, a timeout, and no
API key were indistinguishable — and where `threatLookup` reported a **total provider
outage as `available: true, NO_KNOWN_THREAT`**, cached it 30 min server-side and 30 min
client-side. That was a false "we checked and it's clean" assertion.

Invariants to preserve:

- `status: "UNAVAILABLE"` in `ThreatLookupResponse` is now reachable and is the ONLY
  correct answer when no provider gave coverage. Do not reintroduce a `null` return.
- An `UNAVAILABLE` result is cached for only 60 s (vs 30 min for a real negative).
  A long TTL turns a transient outage into a persistent false negative.
- The extension's threat cache key is versioned (`threatCache:v2`). Bump the version
  whenever the cached shape or the meaning of a cached status changes, or an older
  build's cached "clean" verdicts will be misread as current evidence.
- `ThreatIntelMatch.evidence[].verdict` must be `"unknown"` for a miss. It was
  `"benign"`, which asserts safety from a 12-entry curated list.

## Evidence model (spec §10)

`shared/src/evidence.ts` is the canonical explainability layer: `{ id, type, severity,
confidence, source, title, description, metadata }`. `RiskFactor` remains the scoring
currency; `extension/src/services/scanner/evidenceBuilder.ts` projects one to the other.

- `confidence` is deliberately NOT `severity`. A critical-severity signal can be
  low-confidence (a heuristic); a confirmed provider match is `confirmed`.
- **AI output is never `high` confidence** — model output is capped at `low`.
- `deriveLimitations()` is what stops "unknown" silently becoming "safe". It is
  surfaced in the UI and in scan history; do not drop it to save a few lines.
- `dedupeEvidence()` keys on `type` + normalised description, not `id`, so two rules
  reporting one underlying signal collapse. This is the spec §10 "avoid
  double-counting the same underlying signal" requirement.

## Two-tier sensitive-data model (spec §3)

The content script distinguishes:

- **high-impact** (`password`, `otp`, `card`, `cvv`, `upi`, `banking`) — interrupts
  submission, appears in `HIGH_IMPACT_KINDS`.
- **personal** (phone, DOB, government ID) — detected and reported as evidence, but
  does **not** block.

Phone numbers are requested by nearly every checkout and signup form. Treating them as a
stop condition was a mass false-positive source (spec §3, §21 rule 8). Don't merge the
tiers.

## Scan deduplication (spec §17, §19)

The background worker caches its last successful result in `lastScanByTab` (in-memory
only, 5 min TTL, URL re-checked before reuse). The UI requests it via the
`GET_LAST_SCAN` message.

This exists because `openSidePanelWithWarning` sets a per-tab `?warning=1` path, and the
UI used to run a *second* full scan on open — repeating the content-script injection, the
RDAP and threat lookups, the AI call, and appending a duplicate history entry.

`openSidePanelWithWarning` also **resets the panel path to `sidepanel.html` after
opening**. `chrome.sidePanel.setOptions` is per-tab and sticky; without the reset, every
later manual open on that tab re-enters the warning flow.

`securityApi.sendMessage` is bounded by a 30 s timeout because an MV3 worker killed
mid-request never invokes the callback, which would otherwise leave the UI spinning
forever. It is also callback-based — mocks must *invoke* the callback, not just return
a promise.

Repeat manual scans of an unchanged page are served from an in-memory result cache in
`background/index.ts` (keyed by normalized URL + FNV hash of the cheap,
locally-collected page/redirect signals, 5 min TTL, max 100 entries, cleared on worker
restart). A cache hit skips RDAP, threat-intel, AI, and the history write, and is
marked `cached: true` with `cacheAgeMs` so the UI can show "Cached result · Rescan".
`SCAN_WEBSITE` accepts `force: true` (added to `scanRequestSchema`) to bypass it.
Changed page content ⇒ different hash ⇒ full rescan.

## Privacy hardening (spec §16)

- `sanitizeUrl()` in `groqAnalyzer.ts` redacts sensitive **path segments**, not just
  query strings and fragments. `/reset/<token>`, `/u/jane@example.com/verify`, and
  `/session/<jwt>` all leak through a naive `origin + pathname`. Values are replaced
  with `[token]`/`[email]`/`[redacted]` while the path SHAPE is preserved, so path-based
  rules keep working.
- `pageSignalsSchema` has **no field capable of holding a form value**. That is the
  structural guarantee behind spec §21 rule 1 — a password is unrepresentable, not
  merely filtered. Do not add a `value`-ish field to that schema.
- `getHistory()` / `addHistoryEntry()` store only url, hostname, score, verdict,
  top-4 evidence titles, analysis mode, and timestamp.

## Rate limiting and health (spec §27)

Rate limits are **per-route**, not global. A single global limiter let ordinary browsing
exhaust the AI budget, because `/api/threat-lookup` fires on every page scan. See
`THREAT_RATE_LIMIT_MAX` (default 600) vs `RATE_LIMIT_MAX` (default 20).

`/api/health` is registered **before** the origin check and rate limiters, so an uptime
probe or load-balancer health check (which sends no `Origin`) is not 403'd in production.

## Architecture (scan pipeline — the wiring is in `extension/src/background/index.ts`)

Popup and side panel are the same `App.tsx` with a `variant` prop. Both call
`scanWebsite({tabId})` (`services/api/securityApi.ts`) → `chrome.runtime.sendMessage`
→ background `handleScanWebsite`, which runs in this exact order:

1. read tab URL, reject `chrome://` etc. (`utils/validation.ts`, `utils/url.ts`)
2. inject `content.js` on demand → page signals; `webNavigation` redirect signals only if
   the optional permission was granted (otherwise honestly `null`). Chains persist in
   `chrome.storage.session` (survives worker restarts); listeners register lazily on
   grant via `permissions.onAdded`. Users grant it from Settings → Redirect-chain
   tracking — auto-scan being on does NOT imply the permission was ever requested.
3. RDAP domain-age lookup (`scanner/reputationAnalyzer.ts` → `rdap.org`, 3s timeout)
4. threat intel (`scanner/threatIntelligenceAnalyzer.ts`): composite — backend
   `/api/threat-lookup` first, then a bundled `LOCAL_FEED` of 12 lookalike domains
5. deterministic rule engine (`scanner/index.ts` aggregates `urlAnalyzer`,
   `pageAnalyzer`, `redirectAnalyzer` rules)
6. optional AI (`scanner/aiDecision.ts` → `services/ai/aiAnalyzer.ts` → backend
   `/api/analyze` → Groq)
7. `utils/scoring.ts` (100 − capped deductions) + `scanner/correlationEngine.ts` bonuses
   and `deriveVerdict()`
8. re-check the tab URL, notify the content script, append history

Auto-scan DANGEROUS verdicts take over the tab with `blocked.html`
(`blockTabWithWarning`, session bypass via `BYPASS_BLOCK`, 10-min TTL);
SUSPICIOUS/HIGH_RISK keep the side-panel warning. Manual scans never block.

The content script (`content/index.ts`) has two separate warnings: a visit-time top
banner (`showPageBanner`, fired once per verdict per document on
`SET_SCAN_RISK_STATE` — form or no form) with Leave-this-site / Continue-carefully,
and a submit-time modal (`showSubmitModal`, only on actual interception) with
Cancel / Submit-anyway. "Submit anyway" re-dispatches the stopped action via a
stored retry closure — it never merely closes the dialog. The background probes
`PING` and injects on demand (`ensureContentScript`) before delivering a verdict,
so cached scans that skipped injection still warn. Surprising when testing.

## Invariants that must not be broken

- **Unknown ≠ safe.** Any failed/unavailable threat-intel or RDAP lookup must surface
  `available: false` and be reflected in `DetectionCoverage`. Never cache or default a
  failure to "benign" (`threatIntelligenceAnalyzer.ts`, `server/.../threatLookup.ts`).
- **AI never decides.** AI indicators are additive evidence only; they cannot downgrade a
  deterministic or threat-intel finding. `decideAiNeed()` skips AI entirely when threat
  intel matched.
- **Probabilistic language only.** No "definitely safe/scam" copy in UI, prompts, or docs.
- **No secrets in `extension/`.** `GROQ_API_KEY`, `GOOGLE_SAFEBROWSING_API_KEY` stay in the
  server env. Server must not log request bodies; pino redacts.
- Backend `.env` is loaded relative to the module file (3 candidate paths) so the server
  works from repo root, `server/`, or a container — see `server/src/index.ts`.

## Adding or changing a detection rule

- Rules are plain objects in `urlAnalyzer.ts` / `pageAnalyzer.ts` / `redirectAnalyzer.ts`
  and must be exported through the arrays aggregated in `scanner/index.ts`.
- **Rule id prefixes are load-bearing.** `utils/scoring.ts#groupOf` maps ids to capped
  evidence groups by prefix (`threat-`, `url-`, `page-`, `https-`, `redirect-`,
  plus three hardcoded impersonation ids). A new id with an unknown prefix —
  including `corr-` and `ai-` — silently lands in the `domainIdentity` group
  (cap 40), sharing the cap with domain registration signals. If a new rule
  family needs its own cap, add an explicit branch AND a group entry together.
- If the new rule should justify an AI call, add its id to `AI_TRIGGER_IDS` in
  `scanner/aiDecision.ts`. Weak signals (HTTPS, long URL, odd TLD alone) intentionally do not.
- `correlationEngine.ts` keys off specific factor ids too; add there if the combination matters.
- Brand/lookalike data lives in `utils/domainIdentity.ts` (`BRANDS`, `HOMOGLYPHS`,
  similarity thresholds). `classifyDomain()` is called once per scan; rules must not
  re-derive it.

## Extension build quirks

- Backend URL is **baked in at build time**: `SCAMSHIELD_API_URL` (default
  `http://localhost:8787`) via Vite `define` → `__SCAMSHIELD_API_URL__`. There is no UI to
  set it anymore; `storage.setAiBaseUrl()` is dead code. `SCAMSHIELD_AI_ALWAYS_RUN=true`
  forces an AI call on every scan (dev/test only, costs provider calls).
  These `define`s exist only in `vite.config.ts`, not `vitest.config.ts`.
- The `flattenExtensionHtml` plugin moves `src/popup/index.html` → `dist/popup.html` and
  `src/sidepanel/index.html` → `dist/sidepanel.html` because `public/manifest.json` requires
  those exact root names. Renaming the HTML entries silently breaks the manifest.
- `content/index.ts` must stay a single self-contained chunk (no imports) — it is injected
  via `chrome.scripting`.
- **`content.js` MUST be built as an IIFE.** `wrapContentScriptInIife()` in `vite.config.ts`
  enforces this. `output.format` is `"es"` (the service worker needs a module), which does
  *not* scope a content script's top-level `const`/`let` — they land in the isolated-world
  global scope. Because the background re-injects `content.js` on **every** scan, and scans
  fire from navigation, tab activation, and SPA route changes, a second injection threw
  `SyntaxError: Identifier 'w' has already been declared`, killing the entire script (page
  signals stopped working, message listener vanished).
- Content-script **state must live on `globalThis`** (`__scamshieldContentState`), not in
  module scope. A re-injection re-initialises module `let`s, which would reset `scanVerdict`
  to null and silently disable before-submit protection mid-visit. Installation is guarded by
  `state.installed` so listeners are not stacked.
- `src/content/injection.test.ts` evaluates the **real built `dist/content.js`** in a shared
  Node `vm` context, so it needs `pnpm --filter @scamshield/extension build` to have run
  first. It fails loudly if `dist/content.js` is missing rather than silently passing.
- `verbatimModuleSyntax` is on: type-only imports must use `import type`.
  `@typescript-eslint/no-explicit-any` and `consistent-type-imports` are errors.
- `server` uses `NodeNext` module resolution, so its relative imports need `.js` extensions;
  `extension` uses `bundler` resolution and the `@/` + `@shared/` path aliases.

## Server quirks

- Groq only — `services/groqAnalyzer.ts` makes no provider fallback. The previous
  OpenRouter/OpenAI provider files were deleted in the working tree.
- **Safe Browsing uses a raw `fetch` against the v4 REST endpoint, NOT
  `@googleapis/safebrowsing`.** This is a deliberate deviation from spec §2, which names
  that package: the generated client is a large dependency for a single endpoint, and the
  hand-rolled call gives explicit control over the four required states and the 4 s timeout.
  The unused package was removed from `server/package.json` rather than left as a decoy.
- Env vars read by code and documented in `server/.env.example`:
  `GOOGLE_SAFEBROWSING_API_KEY` (or `GCSB_API_KEY`), `THREAT_FEED_URL` (default OpenPhish
  community feed, refreshed every 30 min in memory, treated as stale after 6 h), `LOG_LEVEL`.
  The server logs a WARN at boot when the Safe Browsing key is absent, because that silently
  removes the strongest threat signal.
- `getFeedStatus()` distinguishes unloaded / stale / fresh. An empty feed must never be
  read as "checked, nothing found".
- `tsup.config.ts` must keep `noExternal: ["@scamshield/shared"]` — `shared` ships raw
  TypeScript (`main: ./src/index.ts`), so leaving it external crashes `node dist/index.js`
  with `ERR_UNKNOWN_FILE_EXTENSION`.
- `NODE_ENV=production` rejects requests with no `Origin` header; with no
  `ALLOWED_EXTENSION_ORIGINS` set, any `chrome-extension://` origin is allowed (dev only).
  `/api/health` is deliberately exempt.
- `analyzeResponseSchema` is the single error envelope. Every `errorHandler` branch parses
  its output through it, so a new error code cannot ship an envelope the extension cannot
  parse. `not_found` was added to the enum for this reason.

## Tests

- Extension tests are colocated as `src/**/*.test.{ts,tsx}` and run in jsdom with a
  hand-rolled `chrome.*` mock at `extension/tests/mocks/chrome.ts`, reset in
  `extension/tests/setup.ts`. Extend the mock rather than reaching for a real API.
- Server tests are `src/**/*.test.ts` in the node environment, no setup file.
- Tests import shared types via `@shared/index`; both `@shared` and `@` aliases are
  configured in `vitest.config.ts`.

## Docs drift (README is behind the code — trust the code)

- README still describes an "enable AI Detection" toggle and a settings field for the AI
  backend URL. Neither exists; AI runs when a base URL is baked in and evidence warrants it.
- README lists Google Safe Browsing as roadmap; it is implemented
  (`server/src/services/safeBrowsing.ts`).
- `docs/DEPLOYMENT.md` is the accurate deploy guide (Render/Railway/Docker, CORS lockdown,
  packaging, troubleshooting). `docs/rule-engine.md` documents the rule categories, points
  model, and anti-false-positive design. `docs/STORE_LISTING.md` is the copy-paste
  source for the Chrome Web Store listing (assets in `Promo_Images/`).

## CI/CD and containers

`.github/workflows/` holds three workflows: `ci.yml` (PRs: build → lint → typecheck
→ test, plus a build-only `docker build`), `deploy-server.yml` (push to main: same
verify, then push `ghcr.io/<owner>/<repo>/scamshield-api` to GHCR and deploy to
Render via `RENDER_DEPLOY_HOOK` and/or EC2 via `EC2_HOST`/`EC2_USER`/`EC2_SSH_KEY`;
absent secrets print a notice and skip — they are never a failure), and
`release-extension.yml` (tag `v*`: build with `SCAMSHIELD_API_URL` baked in, test,
zip, GitHub release, optional Chrome Web Store upload via `CWS_*` secrets).

- The baked API URL lands in `assets/storage-*.js`, **not** `background.js`.
  Verify a production build with `grep -rqF "$URL" extension/dist`.
- `docker-compose.yml` + `Caddyfile` are the self-hosting path (`--profile edge`
  adds automatic HTTPS); `render.yaml` is the Render Blueprint (Dockerfile
  `./server/Dockerfile`, context `.`, `autoDeployTrigger: "off"`).
- `deploy/ec2-user-data.sh` is pasted into EC2 "User data" — it must keep LF
  endings (`.gitattributes` enforces that).
- `refreshFeed()` uses `||`, not `??`, for `THREAT_FEED_URL`: the tracked
  `server/.env.example` ships it empty, and `""` must mean "use the default feed",
  not `fetch("")`.

## Environment notes

- Windows: `clean` scripts use `rm -rf`, which fails under pnpm's default cmd shell — remove
  `dist` manually or run through git bash.
- The root directory is named `open router` (a leftover from the abandoned OpenRouter
  provider work); ignore it when reading paths.
