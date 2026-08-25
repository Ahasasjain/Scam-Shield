# ScamShield — Production Anti-Phishing Implementation Specification

## 1. Objective

Upgrade ScamShield from a heuristic-only URL scanner into a layered, production-oriented anti-phishing product.

The implementation must optimize for:

- high recall for known malicious URLs;
- extremely low false positives on legitimate/popular sites;
- strong detection of unknown phishing through multiple independent signals;
- an explicit UNKNOWN state when evidence is insufficient;
- real threat intelligence;
- explainable verdicts;
- privacy and security by design;
- fast browser performance;
- robust automated regression testing.

### Accuracy requirement

Do **not** promise literal zero false positives or zero false negatives. No real-world security classifier can guarantee that.

Do not use “90% accuracy” as the only target. Measure:

- precision;
- recall;
- F1;
- false-positive rate;
- false-negative rate;
- specificity;
- precision of automatic blocking;
- recall on confirmed phishing;
- performance on legitimate popular domains.

Use fresh, time-separated test data so the system is not tuned against the same URLs it is evaluated on.

---

# 2. Fundamental architectural change

The current system is essentially:

```text
URL
 ↓
heuristic rules
 ↓
100-point score
 ↓
UI
```

Change it to:

```text
Navigation / URL
 ↓
URL normalization
 ↓
Public-Suffix-List domain parsing
 ↓
Domain identity + brand relationship
 ↓
Threat intelligence
 ↓
Fast URL rules
 ↓
Preliminary verdict
 ↓
Page analysis when required
 ↓
Redirect analysis
 ↓
Domain/reputation intelligence
 ↓
Evidence correlation
 ↓
Risk + confidence + coverage
 ↓
UNKNOWN / LOW / SUSPICIOUS / HIGH / DANGEROUS
 ↓
Explainable UI
```

Do not throw away the existing rule engine. Make it one layer.

---

# 3. Core product rule: unknown is not safe

The current scoring architecture must not turn unavailable information into a score of 100.

Search for and eliminate patterns such as:

```ts
return { score: 100 }
```

when:

- threat intelligence is unavailable;
- domain reputation is unavailable;
- page analysis failed;
- URL parsing failed;
- an analyzer crashed.

Instead:

```text
No evidence
≠
Known safe
```

Add an explicit:

```ts
type RiskVerdict =
  | "known_safe"
  | "low_risk"
  | "suspicious"
  | "high_risk"
  | "dangerous"
  | "unknown";
```

Use `unknown` whenever the system lacks enough evidence.

---

# 4. Threat-intelligence layer — highest priority

Create:

```text
extension/src/services/scanner/threatIntelligenceAnalyzer.ts
```

with a provider-neutral interface:

```ts
interface ThreatIntelProvider {
  name: string;

  lookupUrl(input: {
    normalizedUrl: string;
    registrableDomain: string | null;
  }): Promise<ThreatIntelMatch>;
}

interface ThreatIntelMatch {
  available: boolean;
  matched: boolean;

  threatType?: string;
  confidence?: "confirmed" | "high" | "medium";
  source?: string;

  checkedAt: number;
  expiresAt?: number;
}
```

Potential providers, subject to current licensing and API terms:

- Google Safe Browsing or an appropriate commercial equivalent;
- OpenPhish;
- PhishTank;
- VirusTotal URL intelligence;
- commercial URL/domain reputation services;
- internally curated confirmed-malicious feeds;
- user-reported threats after verification.

Do not hard-code a provider into the rest of the scanner.

---

# 5. Protect API credentials

Never ship a privileged third-party API secret inside the browser extension.

Preferred architecture:

```text
Extension
 ↓
ScamShield backend
 ↓
Threat intelligence providers
```

The backend can:

- hide provider secrets;
- cache results;
- rate-limit clients;
- normalize provider responses;
- prevent API abuse.

If a provider explicitly supports browser-safe credentials, follow its documented model.

---

# 6. Threat-intelligence precedence

A confirmed high-quality threat-intelligence match must be able to produce:

```text
DANGEROUS
```

without requiring the URL to also trigger local heuristics.

If a provider says malicious and another says unknown:

```text
do not downgrade to safe
```

Store provider evidence:

```ts
interface ThreatEvidence {
  provider: string;
  verdict: "malicious" | "benign" | "unknown";
  threatType?: string;
  checkedAt: number;
}
```

Do not silently discard provider conflicts.

---

# 7. Local threat cache

Create:

```text
extension/src/services/scanner/threatCache.ts
```

Cache:

```ts
interface CachedThreatResult {
  normalizedUrl: string;
  registrableDomain: string | null;

  matched: boolean;
  threatType?: string;

  provider: string;

  checkedAt: number;
  expiresAt: number;
}
```

Recommended policy:

```text
confirmed malicious → longer TTL
negative/no match    → short TTL
provider unavailable → never cache as safe
```

Use `chrome.storage.local` or the project's existing storage abstraction.

---

# 8. Public Suffix List — mandatory

The current “last two labels” registrable-domain approximation must be removed.

Do not use:

```ts
hostname.split(".").slice(-2)
```

Use a maintained Public Suffix List implementation.

Expose:

```ts
interface ParsedDomain {
  hostname: string;
  publicSuffix: string | null;
  registrableDomain: string | null;
  subdomain: string | null;
}
```

Test at minimum:

```text
example.com → example.com
example.co.uk → example.co.uk
foo.example.co.uk → example.co.uk
foo.github.io → foo.github.io
```

Also test:

- IPv4;
- IPv6;
- localhost;
- malformed hosts;
- IDN/punycode;
- multi-level suffixes.

---

# 9. Domain identity analyzer

Create:

```text
extension/src/services/scanner/domainIdentityAnalyzer.ts
```

It should calculate domain ownership/relationship once and expose it to all rules.

Recommended model:

```ts
type DomainRelationship =
  | "official"
  | "trusted-subdomain"
  | "brand-in-subdomain"
  | "lookalike"
  | "brand-in-registrable-domain"
  | "brand-in-path"
  | "unrelated";

interface DomainIdentity {
  hostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;

  detectedBrands: string[];

  relationships: DomainRelationship[];

  officialDomainMatches: string[];

  normalizedRegistrableDomain?: string;
  similarity?: number;
}
```

---

# 10. Central brand registry

Create a single source of truth:

```ts
interface BrandDefinition {
  id: string;
  displayName: string;
  names: string[];
  officialDomains: string[];
  aliases?: string[];
}
```

Rules:

1. Only include verified official domains.
2. Keep aliases conservative.
3. Do not treat every brand occurrence as impersonation.
4. Support multiple official domains.
5. Do not create per-brand special cases in scanner logic.

---

# 11. Official-domain behavior

These must not trigger brand impersonation or lookalike rules:

```text
https://google.com
https://www.google.com
https://accounts.google.com
https://developers.google.com

https://facebook.com
https://www.facebook.com
https://m.facebook.com
```

Expected:

```text
brand impersonation = false
lookalike = false
```

Do NOT implement:

```ts
if (brand === "google") ...
```

The generic registry/domain relationship algorithm must solve it.

---

# 12. Official domain does not equal universally safe

Do not do:

```ts
if (officialDomain) return score = 100;
```

Official-domain status should suppress:

- brand impersonation;
- lookalike-domain findings caused by the same brand.

It must NOT suppress:

- malicious redirects;
- unsafe page behavior;
- fake warnings;
- compromised content;
- unrelated security findings.

---

# 13. Rewrite brand impersonation

The new algorithm:

```text
1. Parse hostname.
2. Determine registrable domain using PSL.
3. Detect candidate brand.
4. Check whether registrable domain belongs to that brand.
5. If official → no impersonation.
6. If brand is in attacker-controlled subdomain → strong evidence.
7. If registrable domain resembles brand → lookalike analysis.
8. If brand only occurs in path/query → weak evidence.
```

Examples:

```text
accounts.google.com
→ official/trusted-subdomain

google.attacker.example
→ brand-in-subdomain

google-login.attacker.example
→ strong impersonation candidate

g00gle.example
→ lookalike

attacker.example/google/login
→ weak brand-in-path
```

---

# 14. Lookalike detection

Replace binary normalization with:

```text
registrable domain
 ↓
canonicalization
 ↓
Unicode/confusable normalization
 ↓
similarity
 ↓
brand comparison
 ↓
context
 ↓
confidence
```

Recommended result:

```ts
interface LookalikeCandidate {
  brandId: string;
  candidateDomain: string;
  referenceDomain: string;
  similarity: number;
  reasons: string[];
}
```

Potential reasons:

- character substitution;
- character insertion;
- character deletion;
- transposition;
- digit substitution;
- Unicode confusable;
- hyphen insertion;
- repeated character;
- brand + login/security suffix.

Do not make a single normalization match automatically Critical.

---

# 15. Punycode / IDN

Treat:

```text
xn--
```

as a signal, not proof.

Strong evidence is:

```text
IDN/confusable domain
+
brand similarity
+
credential collection
```

not simply:

```text
xn-- exists
```

---

# 16. Weak URL heuristics

Keep these as supporting evidence:

```text
url-excessive-length
url-suspicious-tld
url-nested-subdomains
url-hyphen-overload
url-encoded-chars
url-brand-in-path
```

Suggested starting maximum contributions:

```text
URL length          0–2
Suspicious TLD      0–3
Nested subdomains   0–3
Hyphen overload     0–2
Encoded characters  0–3
Brand in path       0–2
```

These are calibration starting points, not final truth.

---

# 17. Suspicious TLD

Do not treat:

```text
.xyz
.top
.click
```

as malicious by themselves.

Instead:

```text
unusual TLD
+
lookalike
```

should be stronger.

And:

```text
unusual TLD
+
brand impersonation
+
password form
```

should be substantially stronger.

Keep the TLD list data-driven.

---

# 18. Subdomain depth

Do not treat many subdomain labels as a major signal by itself.

This:

```text
a.b.c.example.com
```

can be legitimate.

This is more meaningful:

```text
google.login.attacker.example
```

because the claimed brand is outside the registrable domain.

---

# 19. Brand in path

Keep this very weak.

Examples:

```text
example.com/google
example.com/articles/facebook
github.com/google/material-design
```

must not become high-risk solely because of path text.

Use it as corroborating evidence only.

---

# 20. Evidence groups

Replace unrestricted point accumulation with bounded groups:

```ts
interface EvidenceGroups {
  threatIntel: number;
  domainIdentity: number;
  brandImpersonation: number;
  urlStructure: number;
  pageContent: number;
  transport: number;
  redirects: number;
}
```

Starting caps:

```text
Threat intelligence   decisive/high-confidence
Domain identity       40
Brand impersonation   35
URL structure         15
Page content          30
Transport             20
Redirects             15
```

Do not double-count the same evidence through multiple rules.

---

# 21. Correlation engine

Create:

```text
extension/src/services/scanner/correlationEngine.ts
```

It must detect combinations.

Examples:

```text
lookalike
+
password form
→ strong phishing evidence

brand-in-subdomain
+
password form
+
urgency
→ very strong evidence

brand impersonation
+
password form
+
fake warning
→ critical evidence

suspicious TLD
+
long URL
+
hyphens
→ still weak/moderate
```

Do not add all underlying points a second time.

Use explicit combination rules/bonuses or decision thresholds.

---

# 22. Page analyzer

Keep:

```text
page-login-form
page-payment-form
page-urgency-language
page-giveaway-patterns
page-fake-warnings
```

But login/payment forms alone must remain weak.

Legitimate sites use them constantly.

Add structural form analysis:

```ts
interface FormSignal {
  pageOrigin: string;
  actionOrigin: string | null;

  isCrossOrigin: boolean;
  containsPassword: boolean;
  containsPaymentFields: boolean;
}
```

Never read:

- password values;
- card numbers;
- cookies;
- tokens;
- authentication headers.

---

# 23. Form-action analysis

A page that claims to be a known organization but sends credentials to an unrelated origin is a strong signal.

Example:

```text
claimed brand
+
attacker-controlled page
+
password form
+
cross-origin form action
```

should receive substantial risk.

---

# 24. Resource/iframe analysis

Inspect origins of:

- scripts;
- iframes;
- form actions;
- relevant resources.

Do not flag every third-party CDN.

Use resource-origin evidence only in combination with stronger evidence.

---

# 25. Redirect analysis

The current redirect collection should be implemented.

Track:

```ts
interface RedirectHop {
  url: string;
  origin: string;
  timestamp?: number;
}

interface RedirectSignals {
  hops: RedirectHop[];
  hopCount: number;
  crossOriginHopCount: number;
  origins: string[];
}
```

Do not make redirect count alone highly suspicious.

Prioritize:

```text
multiple cross-origin hops
+
suspicious final destination
```

---

# 26. Automatic navigation scanning

The extension should not depend only on a manual “Scan this website” button.

Use an early fast scan:

```text
navigation
 ↓
URL normalization
 ↓
local threat cache
 ↓
threat intelligence
 ↓
domain identity
 ↓
fast URL rules
 ↓
preliminary verdict
```

After load:

```text
DOM analysis
 ↓
redirect analysis
 ↓
final verdict
```

Use Manifest V3-compatible Chrome APIs and only the minimum permissions required.

---

# 27. Blocking policy

Do not automatically block everything suspicious.

Use:

```text
KNOWN MALICIOUS
→ strong warning/interstitial

HIGH RISK
→ prominent warning + explicit continuation

SUSPICIOUS
→ warning/banner

LOW RISK
→ normal UI

UNKNOWN
→ limited-coverage message
```

Automatic blocking must use a conservative high-confidence threshold.

---

# 28. Reputation analyzer

Turn the current placeholder into a real provider-neutral analyzer.

Potential signals:

- domain age;
- domain reputation;
- IP/ASN reputation;
- registrar;
- DNS characteristics;
- hosting history;
- abuse reports.

Do not make domain age alone decisive.

Example:

```text
new domain
```

is weak.

But:

```text
new domain
+
brand impersonation
+
password form
```

is strong.

---

# 29. Unknown and coverage

Add:

```ts
interface DetectionCoverage {
  url: boolean;
  domainIdentity: boolean;
  threatIntel: boolean;
  page: boolean;
  redirects: boolean;
  reputation: boolean;
}

type Confidence =
  | "high"
  | "medium"
  | "low"
  | "unknown";
```

A result should be able to say:

```text
Risk: Low
Confidence: Medium

Threat intelligence: unavailable
Page analysis: available
Domain analysis: available
```

Do not turn unavailable intelligence into a safe verdict.

---

# 30. Scoring

If the existing 0–100 score is retained, define it as a:

```text
Risk Indicator Score
```

not a probability.

Suggested bands:

```text
0–29    Critical
30–49   High
50–69   Medium
70–84   Low
85–100  No significant indicators detected
```

But the final verdict must be driven by evidence and confidence, not just the arithmetic score.

A confirmed threat-intelligence match must be able to override a high numerical score.

---

# 31. UI

Do not make the primary UI:

```text
Score: 76
```

Use:

### Known malicious

```text
🛑 Dangerous website

Known phishing threat detected.

Why:
• Threat intelligence match
• Brand/domain mismatch
• Credential collection detected

Recommendation:
Leave this page.
```

### Suspicious

```text
⚠ Suspicious website

Why:
• Domain resembles a known organization
• Password form detected
• Domain is not an official organization domain

Recommendation:
Do not enter sensitive information.
```

### Unknown

```text
? Limited information

No known threat was found, but this website could not be fully verified.

Coverage:
✓ URL analysis
✓ Domain analysis
⚠ Threat intelligence unavailable
```

Never say “This website is safe” merely because no rule fired.

---

# 32. Threat-intelligence + heuristic architecture

Final architecture:

```text
                         BROWSER NAVIGATION
                                │
                                ▼
                       ┌─────────────────┐
                       │ URL NORMALIZER  │
                       └────────┬────────┘
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
       ┌──────────────┐ ┌───────────────┐ ┌──────────────┐
       │ Threat Intel │ │ Domain        │ │ URL Rules    │
       │              │ │ Identity      │ │              │
       └──────┬───────┘ └───────┬───────┘ └──────┬───────┘
              └──────────────────┼────────────────┘
                                 ▼
                       ┌──────────────────┐
                       │ FAST RISK ENGINE │
                       └────────┬─────────┘
                                │
                         suspicious?
                                │
                                ▼
                       ┌──────────────────┐
                       │ PAGE ANALYZER    │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ REDIRECT ANALYZER│
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ REPUTATION       │
                       │ ANALYZER         │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ CORRELATION      │
                       │ ENGINE           │
                       └────────┬─────────┘
                                │
                  ┌─────────────┼──────────────┐
                  ▼             ▼              ▼
             THREAT LEVEL   CONFIDENCE     COVERAGE
                  │             │              │
                  └─────────────┼──────────────┘
                                ▼
                       ┌──────────────────┐
                       │ FINAL VERDICT    │
                       └──────────────────┘
```

---

# 33. Test data

Create:

```text
tests/data/benign/
tests/data/phishing/
tests/data/scam/
tests/data/lookalike/
tests/data/edge-cases/
tests/data/known-threats/
```

Benign data must include:

- Google;
- Facebook;
- Microsoft;
- Apple;
- Amazon;
- GitHub;
- banks;
- universities;
- government sites;
- SaaS;
- CDN-heavy sites;
- international domains;
- legitimate uncommon TLDs;
- deep subdomains;
- long legitimate URLs.

Malicious data should include:

- credential phishing;
- payment phishing;
- brand impersonation;
- fake support;
- fake browser warnings;
- giveaways;
- malware distribution;
- QR phishing;
- shortened URLs;
- redirect chains;
- punycode/homographs;
- compromised legitimate sites when reliable labels exist.

---

# 34. Mandatory regression fixtures

Legitimate:

```text
https://google.com
https://www.google.com
https://accounts.google.com
https://developers.google.com

https://facebook.com
https://www.facebook.com
https://m.facebook.com
```

These must not trigger brand impersonation or lookalike findings.

Synthetic attacker-controlled examples:

```text
https://google-login.example.com
https://google.attacker.example
https://g00gle.example
https://paypa1.example
https://facebook-security.example.com
https://example.com/google/login
```

These should exercise the intended domain relationship logic.

---

# 35. Benchmark methodology

Do not claim “90% accurate” based on a tiny hand-picked list.

Create three datasets:

```text
development
validation
final test
```

The final test set must be unseen during rule/threshold tuning.

Prefer time-separated data.

Track:

```text
Benign samples
Malicious samples

True positives
True negatives
False positives
False negatives

Precision
Recall
F1
False-positive rate
False-negative rate

Automatic-block precision
Known-threat recall
Unknown-phishing recall
```

---

# 36. Threshold strategy

Do not optimize a single global score.

Use separate thresholds:

```text
automatic block
strong warning
suspicious warning
informational
```

The automatic-block threshold should prioritize extremely high precision.

This allows the product to maintain high recall through warnings without exposing users to excessive false-positive blocks.

---

# 37. Performance

Target:

```text
fast URL analysis < 50 ms
local rule engine < 10 ms
```

Remote intelligence must have strict timeouts.

If remote lookup times out:

```text
continue local analysis
coverage.threatIntel = false
verdict must not become "known safe"
```

---

# 38. Reliability

The extension must continue operating when:

- provider is unavailable;
- internet is unavailable;
- page HTML is malformed;
- URL is malformed;
- DOM is huge;
- content script cannot execute;
- redirect tracking is unavailable;
- storage fails;
- a rule throws.

One rule must never crash the scanner.

---

# 39. Privacy

Never transmit by default:

- passwords;
- card numbers;
- cookies;
- tokens;
- authentication headers;
- form values;
- complete page HTML.

Prefer sending only the minimum required URL/domain metadata to remote threat intelligence.

Clearly document remote URL checking in the privacy policy.

---

# 40. AI

Keep AI optional.

AI is additional evidence only.

It must not override confirmed threat intelligence.

If:

```text
threat intelligence = confirmed malicious
AI = says safe
```

final result remains:

```text
dangerous
```

AI should never be the only security authority.

---

# 41. Required code changes

At minimum inspect and modify:

```text
extension/src/utils/url.ts
extension/src/services/scanner/urlAnalyzer.ts
extension/src/services/scanner/index.ts
extension/src/utils/scoring.ts
shared/src/risk.ts
extension/src/services/scanner/pageAnalyzer.ts
extension/src/services/scanner/redirectAnalyzer.ts
extension/src/services/scanner/reputationAnalyzer.ts
extension/src/background/index.ts
extension/src/content/index.ts
```

Add as needed:

```text
extension/src/services/scanner/domainIdentityAnalyzer.ts
extension/src/services/scanner/threatIntelligenceAnalyzer.ts
extension/src/services/scanner/threatCache.ts
extension/src/services/scanner/correlationEngine.ts
```

Do not modify files blindly. First inspect the repository and existing interfaces.

---

# 42. Test requirements

Expand:

```text
extension/src/utils/url.test.ts
extension/src/services/scanner/ruleEngine.test.ts
extension/src/utils/scoring.test.ts
```

Add tests for:

- Public Suffix List;
- official domains;
- trusted subdomains;
- attacker subdomains;
- lookalikes;
- punycode;
- brand-in-path;
- suspicious TLD;
- deep subdomains;
- weak-signal accumulation;
- strong-signal correlation;
- threat-intelligence matches;
- provider failures;
- unknown coverage;
- Google regression;
- Facebook regression.

Every production false positive/false negative becomes a permanent regression test.

---

# 43. Build and verification

Before completion run the repository's normal:

```bash
pnpm test
pnpm build
```

and any existing:

```bash
lint
typecheck
```

commands.

Also run the detection benchmark.

Do not report success merely because unit tests pass.

---

# 44. Required final implementation report

After implementation, report:

## Changed files

For every changed file:

```text
path
what changed
why
```

## New dependencies

```text
package
version
reason
```

## New permissions

```text
permission
reason
```

## Network endpoints

List every external endpoint and why it is called.

## Threat-intelligence providers

For each:

```text
provider
data returned
cache policy
failure behavior
privacy implications
```

## Test results

```text
unit tests:
integration tests:
build:
typecheck:
lint:
```

## Detection benchmark

```text
benign:
malicious:

TP:
TN:
FP:
FN:

precision:
recall:
F1:
FPR:
FNR:

automatic-block precision:
known-threat recall:
```

Do not claim >90% unless the measured benchmark actually demonstrates it.

## Known limitations

Be explicit.

---

# 45. Commercial release gate

Do not ship until:

```text
[ ] Known malicious URLs cannot silently receive a clean/safe verdict.
[ ] Threat-intelligence failure cannot become a safe verdict.
[ ] Google/Facebook regression tests pass.
[ ] Public Suffix List is used.
[ ] Brand detection is based on domain relationship, not substring matching.
[ ] Lookalike detection is similarity/context based.
[ ] Login forms alone do not cause high risk.
[ ] Suspicious TLD alone does not cause high risk.
[ ] Long URLs alone do not cause high risk.
[ ] Deep subdomains alone do not cause high risk.
[ ] Strong phishing combinations are detected.
[ ] Automatic blocking uses a conservative high-confidence threshold.
[ ] Unknown sites are clearly labeled.
[ ] No secrets/form values are transmitted.
[ ] Provider credentials are protected.
[ ] Full tests pass.
[ ] Build passes.
[ ] Fresh benchmark data is evaluated.
[ ] FP and FN rates are measured.
[ ] Performance is measured.
[ ] Privacy behavior is documented.
[ ] External threat-feed licensing/terms are reviewed.
```

---

# 46. Final engineering principle

Do not turn ScamShield into a bigger pile of URL heuristics.

The product should answer:

> “Does this domain actually belong to the claimed organization, is it already known to be malicious, does the page behave like a phishing/scam page, and do independent signals reinforce the same conclusion?”

The final system should combine:

```text
Threat intelligence
+
Domain identity
+
URL analysis
+
Page behavior
+
Redirects
+
Reputation
+
Evidence correlation
+
Confidence
+
Coverage
```

The result should be:

```text
KNOWN MALICIOUS
→ dangerous

STRONG MULTI-SIGNAL PHISHING
→ high/dangerous

MEANINGFUL SUSPICION
→ suspicious

INSUFFICIENT EVIDENCE
→ unknown/low-risk

NO SIGNIFICANT INDICATORS
→ not known malicious, never an absolute safety guarantee
```

This is the architecture to implement for a commercially credible product. It is intentionally designed so that high recall and low false positives can be optimized independently rather than forcing every uncertain URL into a binary safe/scam decision.
