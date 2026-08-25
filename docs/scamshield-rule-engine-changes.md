# ScamShield Rule Engine — Required Extension Changes

## Purpose

This document is the implementation plan for correcting the current rule engine so that legitimate sites such as Google and Facebook are not penalized merely because their brand names occur in the hostname, while genuine impersonation and phishing patterns remain detectable.

The existing rulebook establishes a deterministic, explainable, on-device engine with URL, HTTPS, page, redirect, and domain signals. It also explicitly identifies Public Suffix List support, reputation, and redirect-chain collection as future extension points. The changes below preserve that architecture while correcting the domain/brand logic and scoring model.

---

## 1. Critical problems to fix

### 1.1 Brand-name detection is too broad

Current behavior can treat a brand keyword in a hostname as evidence of impersonation.

This is wrong:

```text
accounts.google.com
www.facebook.com
m.facebook.com
developers.google.com
```

A brand appearing in a hostname is not sufficient evidence of impersonation.

The engine must first determine the registrable domain and compare it with the brand's official domains.

---

### 1.2 Registrable-domain detection must not use "last two labels"

The current rulebook says the V1 implementation approximates the registrable domain using the last two labels.

Replace this with Public Suffix List based parsing.

Examples:

```text
accounts.google.com
→ google.com

foo.example.co.uk
→ example.co.uk

foo.bar.github.io
→ bar.github.io
```

Do not implement this with:

```ts
hostname.split(".").slice(-2)
```

Use a maintained Public Suffix List implementation/library.

---

### 1.3 Lookalike detection is too binary

Current homoglyph normalization such as:

```text
0 → o
1 → l
vv → w
rn → m
```

is useful as a signal but should not automatically establish malicious intent.

Replace binary matching with:

1. normalization,
2. similarity calculation,
3. brand/domain context,
4. official-domain exclusion,
5. corroborating evidence.

---

### 1.4 Weak URL signals are being double-counted

These signals can describe the same underlying property:

```text
long URL
many hyphens
deep subdomains
suspicious TLD
encoded characters
brand in path
```

Do not allow all of them to independently accumulate large deductions.

Group related signals and cap their total contribution.

---

### 1.5 The scoring specification is internally inconsistent

The current scoring model subtracts points from 100.

Therefore:

```text
100 - 24 = 76
100 - 26 = 74
100 - 28 = 72
```

A single 24–28 point finding cannot reach the Critical score band of 0–29.

Update the documentation and implementation so severity labels and score behavior agree.

---

# 2. Required new domain model

Create a first-class domain relationship classifier.

Recommended type:

```ts
type DomainRelationship =
  | "official"
  | "trusted-subdomain"
  | "brand-in-subdomain"
  | "lookalike"
  | "brand-in-path"
  | "unrelated";
```

The classifier should produce structured evidence:

```ts
interface DomainIdentity {
  hostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  organizationDomain: string | null;

  detectedBrand?: string;
  matchedOfficialDomain?: string;

  relationship: DomainRelationship;

  normalizedRegistrableDomain?: string;
  similarity?: number;
}
```

Do not make the scanner infer this information repeatedly in individual rules.

Compute it once and put it into `urlSignals` / scan context.

---

# 3. Create a trusted brand/domain registry

Create a central registry instead of scattering brand strings through rules.

Recommended shape:

```ts
interface BrandDefinition {
  id: string;
  names: string[];
  officialDomains: string[];
}
```

Example:

```ts
const BRANDS: BrandDefinition[] = [
  {
    id: "google",
    names: ["google"],
    officialDomains: [
      "google.com",
      // Add only verified official domains.
    ],
  },
  {
    id: "facebook",
    names: ["facebook"],
    officialDomains: [
      "facebook.com",
      "fb.com",
    ],
  },
];
```

Important:

- Keep the registry authoritative.
- Do not treat every brand keyword as an official domain.
- Avoid overly broad brand aliases.
- Prefer exact registrable-domain matching.
- Allow multiple official domains where necessary.
- Keep brand names separate from domain ownership.

---

# 4. Official-domain detection

Implement:

```ts
isOfficialBrandDomain(
  registrableDomain,
  brandDefinition
): boolean
```

Examples:

```text
google.com
→ official Google domain

accounts.google.com
→ official Google domain / trusted subdomain

google.com.attacker.example
→ NOT Google

google.attacker.example
→ NOT Google

facebook.com
→ official Facebook domain

facebook.attacker.example
→ NOT Facebook
```

The important comparison is the registrable domain, not whether the hostname contains the brand.

---

# 5. Trusted subdomain handling

A subdomain of an official registrable domain should inherit the official-domain relationship.

Examples:

```text
accounts.google.com
mail.google.com
developers.google.com
```

should not trigger:

```text
url-brand-impersonation
url-lookalike-domain
```

However, official-domain status must NOT suppress unrelated security findings.

For example, a legitimate domain could still have:

```text
HTTP
malicious redirect
fake warning
```

Therefore:

```text
official domain
≠ automatically safe
```

It only suppresses brand-impersonation findings.

---

# 6. Rewrite `url-brand-impersonation`

Replace the current broad rule.

New logic:

```text
1. Determine registrable domain.
2. Detect whether hostname contains a known brand.
3. Find the brand's official domains.
4. If registrable domain is official:
      return no finding.
5. If brand appears in an attacker-controlled subdomain:
      produce strong impersonation evidence.
6. If brand appears in registrable domain but is not official:
      evaluate for impersonation/lookalike.
7. If brand appears only in path/query:
      produce only weak supporting evidence.
```

Examples:

```text
accounts.google.com
→ no impersonation

google.attacker.com
→ brand-in-subdomain

google-login.attacker.com
→ strong impersonation

g00gle.com
→ lookalike

attacker.com/google/login
→ weak brand-in-path
```

---

# 7. Rewrite lookalike-domain detection

The new lookalike rule must operate on the registrable domain.

Pipeline:

```text
raw hostname
→ registrable domain
→ normalize
→ compare against official brand domains
→ calculate similarity
→ apply contextual threshold
```

Do not trigger merely because normalization produces the same string.

Recommended behavior:

```text
exact official domain
→ no finding

very high similarity + unrelated registrable domain
→ high-risk evidence

moderate similarity
→ weak supporting evidence

low similarity
→ no finding
```

Keep the similarity threshold configurable.

Do not hard-code a single universal threshold without tests.

---

# 8. Brand-in-path rule

Reduce the role of:

```text
url-brand-in-path
```

A brand appearing in a URL path is common and should rarely be significant by itself.

Examples:

```text
example.com/google
example.com/articles/facebook
github.com/google/material-design
```

should not receive a large deduction.

Recommended:

```text
brand-in-path alone
→ 0–2 points maximum
```

It can become meaningful when combined with:

```text
unknown/attacker domain
+
credential form
+
urgency language
```

---

# 9. Reduce weak URL heuristics

Treat these as supporting evidence:

```text
url-excessive-length
url-suspicious-tld
url-nested-subdomains
url-hyphen-overload
url-encoded-chars
```

Recommended approximate maximum contributions:

```text
URL length          0–2
Suspicious TLD      0–3
Nested subdomains   0–3
Hyphen overload     0–2
Encoded characters  0–3
Brand in path       0–2
```

These values are starting points, not final calibrated values.

The important requirement is that they must not overwhelm domain identity or page evidence.

---

# 10. Contextual suspicious-TLD scoring

Do not treat a TLD as inherently malicious.

Bad model:

```text
.xyz → +10
```

Better model:

```text
suspicious TLD
+
lookalike domain
+
credential form
```

should be significantly stronger than:

```text
suspicious TLD alone
```

A legitimate site on an uncommon TLD should not automatically receive a high-risk result.

---

# 11. Contextual nested-subdomain scoring

Do not consider:

```text
a.b.c.example.com
```

malicious merely because it has multiple labels.

The important case is:

```text
google.login.example.com
```

where:

```text
brand = google
registrableDomain = example.com
```

Therefore the brand/domain relationship should carry more weight than subdomain depth.

---

# 12. Introduce evidence groups

Replace unrestricted point addition with grouped evidence.

Recommended groups:

```ts
interface EvidenceGroups {
  domainIdentity: number;
  brandImpersonation: number;
  urlStructure: number;
  pageContent: number;
  transport: number;
  redirects: number;
}
```

Each group should have a maximum contribution.

Suggested starting caps:

```text
Domain identity       40
Brand impersonation   35
URL structure         15
Page content          30
Transport             20
Redirects             15
```

These caps should be tested and tuned against fixtures.

---

# 13. Add correlation rules

The current engine mostly adds independent points. Add explicit combinations.

Examples:

### Weak

```text
suspicious TLD
```

→ low evidence

### Moderate

```text
lookalike domain
```

→ high evidence

### Strong

```text
lookalike domain
+
password form
```

→ very high evidence

### Critical

```text
brand impersonation
+
password form
+
urgency language
```

→ critical

Another strong example:

```text
brand-in-subdomain
+
credential form
+
fake security warning
```

→ critical

The combination engine should not simply duplicate all underlying points.

---

# 14. Positive/trust evidence

Add positive signals.

Examples:

```ts
interface TrustSignals {
  officialBrandDomain: boolean;
  trustedSubdomain: boolean;
  validKnownDomainRelationship: boolean;
}
```

Positive signals should mainly suppress inappropriate rules.

Do NOT simply award:

```text
+20 trust points
```

because a legitimate domain can still be compromised or misconfigured.

Use positive evidence primarily as a rule gate.

---

# 15. Scoring model

Keep the public score at:

```text
0–100
```

but change the implementation from unrestricted deduction to bounded evidence.

Possible conceptual model:

```text
risk =
    domainRisk
  + brandRisk
  + urlRisk
  + pageRisk
  + transportRisk
  + redirectRisk
```

Each category is capped.

Then:

```ts
score = clamp(100 - risk, 0, 100);
```

The score remains deterministic and explainable.

---

# 16. Risk bands

Keep the existing user-facing bands if desired:

```text
85–100  No significant indicators detected
70–84   Low risk
50–69   Medium risk
30–49   High risk
0–29    Critical risk
```

But document clearly:

> The score is an indicator score, not a probability of safety or probability of fraud.

Do not describe:

```text
90 = 90% safe
```

because the score is not statistically calibrated.

---

# 17. Critical verdicts

Do not make a single weak heuristic critical.

Recommended examples of critical conditions:

```text
password-over-http
```

or:

```text
strong brand impersonation
+
credential collection
```

or:

```text
strong brand impersonation
+
fake security warning
```

or:

```text
multiple independent strong phishing signals
```

A lookalike domain alone should normally be High rather than Critical.

---

# 18. HTTPS rules

Keep:

```text
https-not-used
page-password-over-http
```

but avoid treating HTTPS as positive proof of legitimacy.

Correct interpretation:

```text
HTTPS
→ neutral / expected

HTTP
→ negative evidence

HTTP + password
→ strong negative evidence
```

HTTPS should not give a large positive score.

---

# 19. Page-content rules

Keep the existing structural/content signals:

```text
page-login-form
page-payment-form
page-urgency-language
page-giveaway-patterns
page-fake-warnings
```

but use combinations.

For example:

```text
login form
```

alone:

```text
low
```

while:

```text
unknown domain
+
brand impersonation
+
login form
+
urgency
```

is much stronger.

Do not punish legitimate login/payment pages simply because they contain normal authentication UI.

---

# 20. Redirect rules

Keep redirect evidence separate.

Do not automatically assume:

```text
many redirects = scam
```

A legitimate service can have several redirects.

Increase risk primarily for:

```text
multiple cross-origin hops
+
unknown/brand-impersonating destination
```

The destination domain should matter more than redirect count alone.

---

# 21. Required URL analysis output

Refactor `parseUrl()` / URL analysis to return structured data similar to:

```ts
interface UrlSignals {
  hostname: string;
  protocol: string;

  registrableDomain: string | null;
  publicSuffix: string | null;

  detectedBrands: string[];

  domainRelationships: DomainIdentity[];

  isIpHost: boolean;
  isPunycode: boolean;

  urlLength: number;
  subdomainDepth: number;
  hyphenCount: number;
  encodedCharacterCount: number;

  suspiciousTld: boolean;
}
```

This makes rule evaluation much easier and prevents duplicate parsing logic.

---

# 22. Required debug output

During development, add a debug-only representation:

```ts
{
  hostname,
  registrableDomain,
  detectedBrands,
  domainRelationships,
  normalizedDomain,
  similarity,
  triggeredRules,
  evidenceGroups,
  finalRisk,
  finalScore
}
```

This is especially important for debugging Google/Facebook false positives.

Example expected result:

```text
URL:
https://accounts.google.com/login

registrableDomain:
google.com

brand:
google

relationship:
official

brandImpersonation:
false

lookalike:
false
```

---

# 23. Test matrix

Add URL fixtures for all of the following.

## Official domains

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
No brand-impersonation finding
No lookalike finding
```

---

## Brand in attacker subdomain

```text
https://google.attacker.example
https://facebook.login.attacker.example
https://paypal.verify.attacker.example
```

Expected:

```text
brand-in-subdomain
```

---

## Lookalikes

```text
https://g00gle.example
https://faceb00k.example
https://paypa1.example
```

Expected:

```text
lookalike
```

with severity based on similarity and context.

---

## Brand in path

```text
https://example.com/google/login
https://example.com/facebook/security
```

Expected:

```text
weak brand-in-path
```

not a high-risk result by itself.

---

## Suspicious TLD alone

```text
https://myportfolio.example.xyz
```

Expected:

```text
low/no significant risk
```

unless other evidence exists.

---

## Multiple weak URL signals

Test domains with:

```text
long URL
many hyphens
deep subdomains
encoded parameters
unusual TLD
```

Expected:

```text
weak/moderate risk
```

not automatic high/critical.

---

## Strong combinations

Test:

```text
brand impersonation
+
password form
```

and:

```text
brand impersonation
+
password form
+
urgency
```

Expected:

```text
high
critical
```

respectively.

---

# 24. Regression tests for Google/Facebook

These tests are mandatory.

For every official domain:

```ts
expect(findRule("url-brand-impersonation")).toBeUndefined();
expect(findRule("url-lookalike-domain")).toBeUndefined();
```

Also test:

```text
www.google.com
accounts.google.com
mail.google.com
developers.google.com
www.facebook.com
m.facebook.com
```

Do not solve the false positive by adding special-case conditions such as:

```ts
if (hostname === "google.com") ...
```

The solution must work generically for every brand.

---

# 25. Do not create per-brand exceptions

Avoid code like:

```ts
if (brand === "google") ...
if (brand === "facebook") ...
if (brand === "paypal") ...
```

Instead:

```ts
isOfficialBrandDomain(registrableDomain, brand)
```

must handle all brands through the same registry and algorithm.

---

# 26. Files/components that should change

Based on the current rulebook architecture, prioritize these areas:

```text
extension/src/utils/url.ts
```

Changes:

- Public Suffix List integration
- registrable-domain extraction
- hostname normalization helpers

---

```text
extension/src/services/scanner/urlAnalyzer.ts
```

Changes:

- domain relationship classifier
- official-domain checks
- lookalike similarity
- brand-in-subdomain detection
- weaker brand-in-path scoring
- grouped URL evidence

---

```text
extension/src/services/scanner/index.ts
```

Changes:

- make structured domain signals available to all rules
- add correlation/evidence stage
- preserve skipped-rule reporting

---

```text
extension/src/utils/scoring.ts
```

Changes:

- grouped evidence
- category caps
- correlation bonuses/penalties
- deterministic 0–100 score
- preserve category breakdown

---

```text
shared/src/risk.ts
```

Changes:

- align severity definitions with actual score behavior
- document score as an indicator, not probability
- preserve public score bands unless tests show they need recalibration

---

```text
extension/src/services/scanner/pageAnalyzer.ts
```

Changes:

- keep login/payment rules weak
- ensure page signals become stronger mainly through correlation

---

```text
extension/src/services/scanner/redirectAnalyzer.ts
```

Changes:

- avoid over-weighting redirect count
- emphasize cross-origin destination context

---

# 27. Tests that must be updated/added

Expand:

```text
extension/src/utils/url.test.ts
extension/src/services/scanner/ruleEngine.test.ts
extension/src/utils/scoring.test.ts
```

Add tests for:

```text
official domains
trusted subdomains
brand-in-attacker-subdomain
lookalikes
brand-in-path
country-code domains
multi-level public suffixes
punycode
IP hosts
suspicious TLD
weak-signal accumulation
strong-signal correlation
Google regression
Facebook regression
```

The existing test suite should remain green.

---

# 28. Implementation order

Implement in this order:

## Phase 1 — Domain foundation

- [ ] Add Public Suffix List based domain parsing.
- [ ] Add registrable-domain tests.
- [ ] Add official brand/domain registry.
- [ ] Add domain relationship classifier.
- [ ] Add Google/Facebook regression tests.

## Phase 2 — URL rules

- [ ] Rewrite brand impersonation.
- [ ] Rewrite lookalike detection.
- [ ] Reduce brand-in-path.
- [ ] Reduce weak URL signal weights.
- [ ] Add contextual TLD handling.
- [ ] Add contextual subdomain handling.

## Phase 3 — Scoring

- [ ] Introduce evidence groups.
- [ ] Add category caps.
- [ ] Add correlation rules.
- [ ] Reconcile severity with score bands.
- [ ] Update score tests.

## Phase 4 — Page/redirect integration

- [ ] Keep login/payment as weak signals.
- [ ] Strengthen suspicious combinations.
- [ ] Contextualize redirect risk.
- [ ] Ensure official-domain status does not suppress unrelated security findings.

## Phase 5 — Regression testing

- [ ] Run all existing tests.
- [ ] Add official-domain fixtures.
- [ ] Add phishing fixtures.
- [ ] Verify legitimate sites don't become high-risk.
- [ ] Verify strong phishing combinations remain high/critical.

---

# 29. Acceptance criteria

The implementation is complete only when all of these are true:

### Legitimate domains

```text
google.com
www.google.com
accounts.google.com
facebook.com
www.facebook.com
```

do not receive brand-impersonation or lookalike findings.

### Attacker domains

```text
google.attacker.example
google-login.attacker.example
g00gle.example
```

produce meaningful impersonation evidence.

### Weak anomalies

A suspicious TLD, several hyphens, long URL, or deep subdomain structure alone cannot produce Critical risk.

### Strong combinations

Brand impersonation + credential collection + deceptive content can produce Critical risk.

### Official domains

Being an official domain suppresses only brand-impersonation/lookalike findings, not HTTPS, redirect, or page-content security findings.

### Score

The score remains deterministic, bounded to:

```text
0–100
```

and is explicitly described as an indicator score rather than a probability.

### Explainability

Every deduction can be traced to:

```text
rule
→ evidence
→ category
→ contribution
→ final score
```

---

# 30. Final design principle

The engine should evolve from:

```text
"How many suspicious URL characteristics did I find?"
```

to:

```text
"Does this domain actually belong to the claimed organization,
and do independent signals support the hypothesis that the page
is attempting to deceive the user?"
```

That distinction is the key fix for the Google/Facebook false positives while preserving the deterministic and explainable design of ScamShield.

