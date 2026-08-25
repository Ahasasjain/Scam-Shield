# Rule-Based Detection Engine

This document explains **how ScamShield detects scam and phishing websites without any network or AI dependency** — entirely in the browser, in milliseconds, with explainable, deterministic rules.

> **Source of truth:** the engine is implemented in [`extension/src/services/scanner/`](../extension/src/services/scanner/). Every rule below maps 1:1 to a real rule object in that directory.

---

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Detection philosophy](#2-detection-philosophy)
3. [Pipeline: from URL to score](#3-pipeline-from-url-to-score)
4. [The five rule categories](#4-the-five-rule-categories)
   - [4.1 URL rules](#41-url-rules)
   - [4.2 HTTPS / transport rules](#42-https--transport-rules)
   - [4.3 Page-content rules](#43-page-content-rules)
   - [4.4 Redirect rules](#44-redirect-rules)
   - [4.5 Domain rules](#45-domain-rules)
5. [Severity and points model](#5-severity-and-points-model)
6. [Scoring algorithm](#6-scoring-algorithm)
7. [Anti-false-positive design](#7-anti-false-positive-design)
8. [Privacy guarantees](#8-privacy-guarantees)
9. [Performance characteristics](#9-performance-characteristics)
10. [Testing strategy](#10-testing-strategy)
11. [Extension points and future work](#11-extension-points-and-future-work)

---

## 1. Goals and non-goals

### Goals

- **Deterministic** — same input always produces the same output. No model weights, no randomness, no remote calls. Testable, auditable, reproducible.
- **Explainable** — every finding is a `RiskFactor` with a `title`, `description`, `severity`, `points`, and `source`. The UI never shows "you got 42 points" — it shows _why_.
- **Privacy-first** — by design, all rules run on metadata the extension already has access to (`chrome.tabs.get`, the URL bar, the DOM via an on-demand content script). No traffic is sent off-device for rule execution.
- **Fast** — rule execution is sub-millisecond; total scan (URL parse + rules + UI render) stays well under 300 ms.
- **Probabilistic, not absolute** — the engine never claims a site is "definitely safe" or "definitely a scam". The UI uses phrases like "No significant indicators detected" and "indicators suggest caution" (spec §43).
- **Single weak heuristic never decisive** — severity/point calibration guarantees a critical verdict only emerges from combinations of findings.

### Non-goals

- Not a perfect classifier. It is a _signal_ generator; the goal is to surface explanations, not make authoritative safety claims.
- Not a replacement for Safe Browsing, VirusTotal, or a human review. The `reputationAnalyzer` and AI analyzer are the integration points for those.
- Not a behavioral / network monitor. V1 examines only what the extension can observe in a single tab.

---

## 2. Detection philosophy

Scam and phishing pages are written by humans trying to mimic legitimate ones, so they leave **structural fingerprints** the rule engine can detect. We group those fingerprints into five categories:

| Category              | What it inspects                     | Why it works                                                                                                            |
| --------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| **URL**               | Structure of the URL itself          | Phishers register disposable domains; they manipulate the hostname to look familiar.                                    |
| **HTTPS / transport** | Encryption + transport-level signals | Phishers still commonly run on plain HTTP; password fields on HTTP are a critical risk regardless of intent.            |
| **Page**              | DOM and on-screen text               | Phishing pages have specific content patterns (urgency, fake warnings, giveaways) that legitimate sites rarely combine. |
| **Redirect**          | Navigation chain                     | Phishers funnel victims through multiple short-lived domains.                                                           |
| **Domain**            | Reputation, age, registrar           | Phishers register domains minutes before use; legitimate brands have years of history.                                  |

Each rule is **independent**. The engine runs every rule that can be evaluated against the available context and returns a list of `RiskFactor` objects. **The final score is a function of _how many_ and _how severe_ the findings are**, not any one rule's verdict.

---

## 3. Pipeline: from URL to score

```
[Active tab]
    │
    │  chrome.tabs.get(tabId)
    ▼
URL (string) ──▶ parseUrl() ──▶ urlSignals (object)
    │
    │  chrome.scripting.executeScript + tabs.sendMessage
    ▼
pageSignals (object) — only if permission allows DOM access
    │
    │  collectRedirectSignals() (currently a stub; left as integration point)
    ▼
redirectSignals (object) — only if webNavigation permission granted
    │
    │  collectDomainSignals() — currently returns "unavailable" honestly
    ▼
domainSignals (object)
    │
    │  runRuleEngine(ScanContext)  ◀── the heart of the engine
    ▼
RuleEngineResult { factors: RiskFactor[]; skippedRuleIds: string[] }
    │
    │  optional HttpAIAnalyzer.analyze()  (only if AI toggle is on)
    ▼
AiAnalysisResult
    │
    │  calculateScore(ruleFactors, aiFactors)
    ▼
ScoreResult { score: 0-100; riskLevel; breakdown[] }
```

**Where the work happens:**

- [`extension/src/background/index.ts`](../extension/src/background/index.ts) — orchestrates the pipeline
- [`extension/src/services/scanner/index.ts`](../extension/src/services/scanner/index.ts) — `runRuleEngine()` iterates `ALL_RULES` and returns findings
- [`extension/src/utils/scoring.ts`](../extension/src/utils/scoring.ts) — `calculateScore()` aggregates findings into a 0-100 score

---

## 4. The five rule categories

### 4.1 URL rules

Source: [`extension/src/services/scanner/urlAnalyzer.ts`](../extension/src/services/scanner/urlAnalyzer.ts). All rules in this file are `category: "url"`.

| Rule id                   | Severity | Points | What it detects                                                                                                                                                                  |
| ------------------------- | -------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url-excessive-length`    | low      | 6      | URL longer than 120 characters — common in obfuscated phishing links.                                                                                                            |
| `url-ip-host`             | high     | 18     | Host is a raw IPv4 address (e.g. `http://192.168.1.1/login`). Legitimate brands almost never serve login pages from bare IPs.                                                    |
| `url-suspicious-tld`      | medium   | 10     | TLD is in a list of frequently-abused suffixes (`zip`, `mov`, `tk`, `ml`, `xyz`, `top`, …). Not a verdict on its own — many legitimate sites use these TLDs.                     |
| `url-punycode`            | high     | 16     | Hostname contains `xn--` (punycode). Used to render lookalike characters that mimic trusted brands.                                                                              |
| `url-lookalike-domain`    | critical | 24     | Registrable domain matches a known brand after applying a homoglyph normalization table (`0→o`, `1→l`, `vv→w`, `rn→m`, …). Example: `paypa1.com` → `paypal` after normalization. |
| `url-brand-impersonation` | high     | 20     | Hostname contains a brand keyword but the registrable domain is _not_ the brand's official domain (e.g. `paypal.secure-login.evil.xyz`).                                         |
| `url-nested-subdomains`   | medium   | 10     | Three or more subdomain levels — classic pattern of `login.bank.com.evil.io`.                                                                                                    |
| `url-hyphen-overload`     | low      | 6      | Three or more hyphens in the hostname — throwaway phishing domains often have several.                                                                                           |
| `url-encoded-chars`       | medium   | 8      | Five or more percent-encoded sequences in the URL — used to hide the true destination.                                                                                           |
| `url-brand-in-path`       | low      | 5      | A brand name appears in the path or query of an unrelated domain (after we've already ruled out full impersonation).                                                             |

**Implementation notes:**

- The homoglyph map and brand list are private constants in [`urlAnalyzer.ts`](../extension/src/services/scanner/urlAnalyzer.ts).
- The registrable-domain approximation is "last two labels" — adequate for V1; a Public Suffix List integration is a future improvement.
- Suspicious TLD and shortener lists are intentionally data-driven (single `Set<string>` constant) so they can be updated without code changes.

### 4.2 HTTPS / transport rules

Source: [`extension/src/services/scanner/pageAnalyzer.ts`](../extension/src/services/scanner/pageAnalyzer.ts) (`httpsRules` array). Category `"https"`.

| Rule id                   | Severity | Points | What it detects                                                                                                                                                                |
| ------------------------- | -------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `https-not-used`          | medium   | 12     | The page is served over plain HTTP. Encryption is missing; anything typed can be intercepted. Note the explicit UI text: _HTTPS does not guarantee legitimacy_.                |
| `page-password-over-http` | critical | 28     | A password input is present on an unencrypted HTTP page. Credentials could be intercepted in transit. The single most decisive rule — if it fires, the user should not log in. |

### 4.3 Page-content rules

Source: [`extension/src/services/scanner/redirectAnalyzer.ts`](../extension/src/services/scanner/redirectAnalyzer.ts) (`contentRules` array). Category `"page"`. These rules evaluate signals collected by the **on-demand content script** ([`extension/src/content/index.ts`](../extension/src/content/index.ts)) — never raw page contents.

| Rule id                  | Severity | Points | What it detects                                                                                                                       |
| ------------------------ | -------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `page-login-form`        | low      | 5      | Page contains a password input. Common on legitimate sites, so low severity.                                                          |
| `page-payment-form`      | low      | 5      | Page contains card-number inputs (matched by `autocomplete="cc-number"`, `name*="card"`, etc.). Low severity for the same reason.     |
| `page-urgency-language`  | medium   | 10     | Two or more urgency phrases detected in visible body text (e.g. "act now", "account suspended", "immediate action required").         |
| `page-giveaway-patterns` | high     | 16     | Any giveaway / prize language ("you've won", "claim your reward", "free iPhone").                                                     |
| `page-fake-warnings`     | critical | 26     | Any fake security warning pattern ("your computer has a virus", "browser has been blocked"). Imitates OS or browser security dialogs. |

**Why these are independent checks, not a single "phishy content" score:**

- Each pattern has been seen in real phishing kits but is rare in legitimate UI
- Combining them as evidence makes the verdict interpretable
- The content script only inspects _up to 50 KB_ of visible text ([`slice(0, 50_000)`](../extension/src/content/index.ts)) to avoid expensive DOM traversal on large pages

### 4.4 Redirect rules

Source: [`extension/src/services/scanner/redirectAnalyzer.ts`](../extension/src/services/scanner/redirectAnalyzer.ts) (`redirectRules` array). Category `"redirect"`.

| Rule id                 | Severity | Points | What it detects                             |
| ----------------------- | -------- | ------ | ------------------------------------------- |
| `redirect-long-chain`   | low      | 6      | Four or more redirects in the chain.        |
| `redirect-cross-origin` | medium   | 12     | Two or more cross-origin hops in the chain. |

**Note:** redirect analysis requires the optional `webNavigation` permission. V1 reports "unavailable" honestly when it isn't granted. The architecture is in place; this is the next obvious feature.

### 4.5 Domain rules

Source: [`extension/src/services/scanner/pageAnalyzer.ts`](../extension/src/services/scanner/pageAnalyzer.ts) (`domainRules` array — empty for V1).

**V1 has no rule in this category on purpose.** Domain age, WHOIS, and reputation all require an external data source. Rather than fabricate values, [`reputationAnalyzer.ts`](../extension/src/services/scanner/reputationAnalyzer.ts) returns:

```ts
{
  available: false,
  reason: "Domain intelligence (age, registrar, reputation) is not configured. No values are shown rather than guessed."
}
```

This is the designed integration point for future providers (e.g. a paid WHOIS API, a local Passive DNS feed).

---

## 5. Severity and points model

Defined in [`shared/src/risk.ts`](../shared/src/risk.ts) and used uniformly by every rule:

```ts
type Severity = "low" | "medium" | "high" | "critical";
```

Points are integers. They represent the **deduction** applied to a perfect score of 100. The scoring engine clamps the result to `[0, 100]`.

### Severity → point ranges

The points for each severity are calibrated so that:

- A **single `low`** finding can't push the score below "Low risk" (score 70+)
- A **single `medium`** can reach "Medium risk" but not "High risk"
- **`high` × 2** can reach "High risk"
- A **`critical`** can reach "Critical" on its own
- Combinations, not single rules, are what push into red bands

| Severity   | Typical point range | Effect when alone                                                |
| ---------- | ------------------- | ---------------------------------------------------------------- |
| `low`      | 5 – 6               | Lowest band; one or two alone are not decisive.                  |
| `medium`   | 8 – 12              | Two mediums can reach "Medium risk".                             |
| `high`     | 16 – 20             | One high + one medium = "High risk" likely.                      |
| `critical` | 24 – 28             | One critical alone is enough to enter "Critical" or "High" band. |

This calibration is the reason we say _"a single weak heuristic never flags a site as malicious"_. The `password-over-http` rule is the only one deliberately calibrated to be a one-shot hard stop.

---

## 6. Scoring algorithm

[`extension/src/utils/scoring.ts`](../extension/src/utils/scoring.ts):

```ts
function calculateScore(ruleFactors, aiFactors): ScoreResult {
  const allFactors = [...ruleFactors, ...aiFactors];
  const totalDeduction = allFactors.reduce((sum, f) => sum + f.points, 0);
  const score = clampScore(100 - totalDeduction);

  // Per-category breakdown for "Why this score?"
  const byCategory = new Map<string, number>();
  for (const factor of allFactors) {
    const category = factor.id.startsWith("ai-") ? "ai" : categoryOf(factor.id);
    byCategory.set(category, (byCategory.get(category) ?? 0) + factor.points);
  }
  // ...

  return { score, riskLevel: scoreToRiskLevel(score), breakdown };
}
```

### Score bands (spec §13)

| Score    | Risk level | User-facing label                    |
| -------- | ---------- | ------------------------------------ |
| 0 – 29   | `critical` | "Critical risk"                      |
| 30 – 49  | `high`     | "High risk"                          |
| 50 – 69  | `medium`   | "Medium risk"                        |
| 70 – 84  | `low`      | "Low risk"                           |
| 85 – 100 | `safe`     | "No significant indicators detected" |

Bands live in [`shared/src/risk.ts`](../shared/src/risk.ts) (`SCORE_BANDS`). The `scoreToRiskLevel` function is the single place this mapping is defined, used by both the engine and the UI.

### AI + rule combination

When AI is enabled, its indicators are added with the same shape but `source: "ai"`. AI findings **add deductions** but cannot _clear_ rule findings. This is by design — we never let an LLM override deterministic security signals. Each finding is rendered separately in the UI and labelled with its `source`.

### "Why this score?" breakdown

The score breakdown groups deductions by category (`url`, `https`, `page`, `redirect`, `ai`). The UI renders this as a list of horizontal bars in the `WhyThisScore` component so the user can see at a glance which categories contributed.

---

## 7. Anti-false-positive design

False positives are the most damaging failure mode for a security tool. The engine is biased toward conservatism in several ways:

1. **No rule alone is decisive.** Even `url-lookalike-domain` (critical, 24 pts) only drops the score to 76, which is still "Low risk". The critical band is reached when critical-severity findings **combine** with other indicators.
2. **Subdomain depth, hyphen count, and TLD are low/medium severity.** A legitimate site with a `company-name.io` URL is not punished.
3. **The "HTTPS ≠ safe" stance is hard-coded into the UI** ([`RecommendationCard.tsx`](../extension/src/components/RecommendationCard.tsx)). The "safe" label is "No significant indicators detected" — never "Safe".
4. **Skipped rules are recorded, not silently dropped.** The `RuleEngineResult.skippedRuleIds` array reports which rules were skipped because their signals weren't collected. A future improvement can render a "5 of 15 rules could not be evaluated" banner.
5. **Failing rules never break the scan.** `runRuleEngine` wraps each `evaluate` in a try/catch and records the failure as a skip. A bug in one rule can't prevent other rules from running.

---

## 8. Privacy guarantees

The rule engine is fully **on-device**. It does not:

- Make any network request
- Read form field values (only structural attributes like `type="password"` or `autocomplete="cc-number"`)
- Read cookies, tokens, or authentication headers
- Read full page text (only first 50 KB of visible text)
- Transmit scan results off-device unless AI mode is enabled and the user explicitly turns it on

The on-demand content script ([`extension/src/content/index.ts`](../extension/src/content/index.ts)) is injected only when the user clicks "Scan this website" — never on page load — and is removed automatically by Chrome when the tab closes. Permission for `webNavigation` is **optional** and must be explicitly granted by the user.

---

## 9. Performance characteristics

Designed for the spec target of < 1 s rule-based scan (spec §31):

| Stage                         | Cost                   | Notes                                                                |
| ----------------------------- | ---------------------- | -------------------------------------------------------------------- |
| URL parse (`parseUrl`)        | < 1 ms                 | Single `URL` constructor + small heuristic checks.                   |
| Page signal collection        | 5 – 50 ms              | One `chrome.scripting.executeScript` round-trip + bounded DOM query. |
| Rule engine (`runRuleEngine`) | < 1 ms                 | 15+ rules × O(1) checks each, no async.                              |
| Scoring (`calculateScore`)    | < 0.1 ms               | One reduce + one map.                                                |
| **Total**                     | **10 – 80 ms** typical | Plus ~100 ms for storage I/O and the AI toggle check.                |

A failing rule or missing signal is handled with O(1) bookkeeping; nothing in the engine has hot loops over page data.

---

## 10. Testing strategy

Tests live next to the code they cover and are picked up by the workspace `vitest` config:

- [`extension/src/utils/url.test.ts`](../extension/src/utils/url.test.ts) — 14 tests covering every URL heuristic against both safe and malicious fixtures
- [`extension/src/services/scanner/ruleEngine.test.ts`](../extension/src/services/scanner/ruleEngine.test.ts) — 7 tests verifying the engine combines rules correctly, skips rules when signals are absent, and never throws on adversarial input
- [`extension/src/utils/scoring.test.ts`](../extension/src/utils/scoring.test.ts) — 5 tests covering the five score bands, clamping, AI-factor integration, and category breakdown
- [`extension/src/components/components.test.tsx`](../extension/src/components/components.test.tsx) — 9 component tests covering the AI toggle, score display, history, and the "No significant indicators" copy

The full suite runs in ~13 s and must pass before any commit (see `pnpm test`).

---

## 11. Extension points and future work

| Future addition                                            | Where it slots in                                                                                                                                                        | Status                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- |
| Public Suffix List for proper registrable-domain detection | [`url.ts`](../extension/src/utils/url.ts)                                                                                                                                | Designed, not implemented |
| Real WHOIS / domain age                                    | [`reputationAnalyzer.ts`](../extension/src/services/scanner/reputationAnalyzer.ts) returns `{ available: false, reason }` — single function to replace                   |
| Google Safe Browsing API                                   | A new analyzer in [`scanner/`](../extension/src/services/scanner/) following the `DetectionRule` contract, then composed in `runRuleEngine`                              | Designed                  |
| Real redirect chain (webNavigation listener)               | `collectRedirectSignals()` in [`background/index.ts`](../extension/src/background/index.ts) is the placeholder; permission is already declared as `optional_permissions` | Designed                  |
| VirusTotal / URLScan                                       | A second AI-shaped analyzer following the same `interface` in [`aiAnalyzer.ts`](../extension/src/services/ai/aiAnalyzer.ts)                                              | Designed                  |
| Domain reputation with local cache                         | Wraps `reputationAnalyzer` and stores results in `chrome.storage.local` with a TTL                                                                                       | Designed                  |

The rule engine contract — `DetectionRule { id; name; description; severity; points; category; evaluate(ctx) }` — is the only thing new analyzers need to satisfy to participate in the scoring system. Adding a new check is therefore a 10-line change to one file.
