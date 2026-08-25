# ScamShield — Production-Ready Chrome Extension

Build a **production-ready Chrome Extension called "ScamShield"** that detects potentially fake, malicious, phishing, and scam websites.

The extension must have a **modern, polished, professional security-product UI** and support two detection modes:

1. **Rule-Based Detection**
2. **AI-Based Detection**

The user must be able to switch AI detection ON/OFF using a prominent toggle.

---

## 1. Product Overview

ScamShield is a browser security extension that analyzes the currently opened website and provides a security/risk assessment.

The primary user experience should be:

> Open website → Click ScamShield → Analyze → Get security score + reasons + recommendations

Example result:

```text
SCAMSHIELD

Security Score
━━━━━━━━━━━━━━━━
        82
      SAFE

✓ HTTPS enabled
✓ Valid SSL certificate
✓ Domain established
✓ No suspicious redirects detected
✓ No obvious phishing indicators

AI Analysis
━━━━━━━━━━━━━━━━
AI confidence: 91%

No significant scam indicators detected.
```

For a suspicious website:

```text
Security Score
━━━━━━━━━━━━━━━━
        24
      HIGH RISK

⚠ Domain registered recently
⚠ Suspicious URL structure
⚠ Login form detected
⚠ Multiple redirects
⚠ Domain reputation concerns

Recommendation:
Do not enter passwords, payment information,
or personal information on this website.
```

---

# 2. Core Requirements

Build this as a real production-quality Chrome Extension using:

- Manifest V3
- NEXT
- TypeScript
- Vite
- Modern CSS or Tailwind CSS
- Chrome Extension APIs
- Proper component architecture
- Strong TypeScript typing
- Secure coding practices
- ESLint
- Prettier
- Unit/component tests
- Error handling
- Loading states
- Empty states
- Accessibility
- Responsive UI

Do NOT create a simple demo or mockup.

The code should be structured so it can realistically be published to the Chrome Web Store after configuration and security review.

---

# 3. Architecture

Use a clean architecture similar to:

```text
scamshield/
│
├── src/
│   ├── background/
│   │   └── index.ts
│   ├── content/
│   │   └── index.ts
│   ├── popup/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── components/
│   ├── sidepanel/
│   │   ├── App.tsx
│   │   └── components/
│   ├── components/
│   │   ├── SecurityScore.tsx
│   │   ├── RiskBadge.tsx
│   │   ├── DetectionResult.tsx
│   │   ├── RiskFactors.tsx
│   │   ├── AIAnalysis.tsx
│   │   ├── ScanProgress.tsx
│   │   ├── AIModeToggle.tsx
│   │   ├── WebsiteInfo.tsx
│   │   └── ErrorState.tsx
│   ├── services/
│   │   ├── scanner/
│   │   │   ├── ruleEngine.ts
│   │   │   ├── urlAnalyzer.ts
│   │   │   ├── redirectAnalyzer.ts
│   │   │   ├── pageAnalyzer.ts
│   │   │   └── reputationAnalyzer.ts
│   │   ├── ai/
│   │   │   └── aiAnalyzer.ts
│   │   └── api/
│   │       └── securityApi.ts
│   ├── types/
│   │   ├── scan.ts
│   │   ├── risk.ts
│   │   └── ai.ts
│   ├── utils/
│   │   ├── url.ts
│   │   ├── scoring.ts
│   │   ├── storage.ts
│   │   └── validation.ts
│   └── styles/
├── public/
│   └── icons/
├── tests/
├── manifest.json
├── package.json
├── tsconfig.json
├── vite.config.ts
├── eslint.config.js
├── prettier.config.js
└── README.md
```

You may improve this structure if there is a better production architecture.

---

# 4. Manifest V3

Use Chrome Manifest V3.

The manifest should use the minimum permissions necessary.

Potential APIs may include:

- `activeTab`
- `storage`
- `scripting`
- `tabs`
- `webNavigation`
- `sidePanel`

Do NOT request broad permissions such as `<all_urls>` unless absolutely required.

If a feature genuinely requires additional permissions, explain why and isolate the permission.

Follow Chrome Web Store security and privacy best practices.

---

# 5. Modern UI

Create a premium cybersecurity dashboard.

Design characteristics:

- Modern
- Minimal
- Professional
- Security-focused
- Clean typography
- Rounded cards
- Subtle shadows
- Smooth animations
- Clear hierarchy
- Excellent spacing
- Accessible contrast
- Responsive
- Dark mode support

Avoid generic bootstrap-looking UI, excessive gradients/animations, clutter, fake statistics, and unnecessary decorative elements.

Use a security-product visual language inspired by modern security products, but do NOT copy their branding.

---

# 6. Main Dashboard

The popup/side panel should contain a ScamShield header, website-security status, and a prominent AI Detection ON/OFF toggle.

Display the current website, scan status, security score, risk level, important findings, and recommendations.

---

# 7. AI Toggle

When AI is ON:

- Rule-based scan enabled
- AI analysis enabled

When AI is OFF:

- Rule-based scan enabled
- AI analysis disabled

Persist the toggle state using `chrome.storage.local`.

Default: **AI = OFF**. The user must explicitly enable AI.

---

# 8. Rule-Based Detection Engine

Implement a deterministic rule engine. Do NOT fake results.

```ts
interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  evaluate(context: ScanContext): RuleResult;
}
```

Implement URL analysis for:

- Excessive URL length
- Suspicious subdomains
- IP address instead of domain
- Excessive hyphens
- Suspicious characters
- URL encoding abuse
- Lookalike domains
- Punycode
- Suspicious TLD patterns
- Brand impersonation patterns
- Multiple nested subdomains

Do not classify a website as malicious solely because of one weak heuristic.

---

# 9. HTTPS / SSL

Check HTTPS/HTTP usage, mixed content where detectable, and certificate-related information where safely available.

HTTPS should NOT automatically mean SAFE.

Explain that HTTPS encrypts traffic but does not guarantee that a website is legitimate.

---

# 10. Domain Intelligence

Where permitted and available through a backend/API, analyze:

- Domain age
- Registration information
- Registrar
- DNS information
- Reputation
- Known malicious indicators

Do not bypass browser security restrictions. If information is unavailable, show **Information unavailable** rather than fabricating values.

---

# 11. Redirect Analysis

Detect suspicious redirect behavior where technically possible and display redirect chains. Flag suspicious behavior without assuming every redirect is malicious.

---

# 12. Page Content Analysis

Potential indicators:

- Password/login forms
- Payment forms
- Requests for sensitive information
- Suspicious popups
- Fake security warnings
- Urgency language
- Giveaway/scam patterns
- Impersonation indicators
- Suspicious external resources

Minimize collected data. Do not transmit full webpage contents to third-party services by default.

---

# 13. Risk Scoring System

Create a transparent scoring algorithm:

- 0–29: Critical Risk
- 30–49: High Risk
- 50–69: Medium Risk
- 70–84: Low Risk
- 85–100: Safe / No significant indicators detected

Avoid implying that a score guarantees safety.

```ts
interface RiskFactor {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  points: number;
  source: "rule" | "ai";
}
```

Every score must be explainable.

---

# 14. AI Detection Mode

When AI mode is enabled, send only the minimum necessary security metadata to the AI service.

```json
{
  "url": "...",
  "hostname": "...",
  "urlSignals": [],
  "pageSignals": [],
  "redirectSignals": [],
  "domainSignals": []
}
```

Do NOT blindly send passwords, cookies, authentication tokens, session information, payment details, personal information, or complete private webpages.

---

# 15. AI Provider Architecture

Do not hardcode a provider into UI components.

```ts
interface AIAnalyzer {
  analyze(context: AIAnalysisContext): Promise<AIAnalysisResult>;
}
```

Use:

```text
Chrome Extension
       ↓
Backend API
       ↓
AI Provider
       ↓
Structured Security Result
       ↓
Chrome Extension
```

Never expose a private production AI API key inside the extension.

---

# 16. AI Result

AI should return structured JSON with risk level, confidence, summary, indicators, and recommendation.

Validate responses using a runtime schema such as Zod. Do not trust arbitrary AI output.

---

# 17. Combining Rule + AI Results

When AI is enabled, combine deterministic rule-engine findings with AI analysis.

Do not allow AI to completely override deterministic security signals.

Clearly distinguish:

- Rule-based findings
- AI findings

---

# 18. AI Failure Handling

If AI fails, show:

> AI analysis unavailable. Your rule-based security scan is still available.

Handle timeout, network failure, invalid AI response, rate limits, authentication errors, and server errors.

---

# 19. Scan Flow

```text
Detect current tab
        ↓
Validate URL
        ↓
Collect permitted metadata
        ↓
Run rule engine
        ↓
If AI enabled
        ↓
Run AI analysis
        ↓
Combine results
        ↓
Calculate risk
        ↓
Display result
```

Show real scan progress without artificially slowing scanning.

---

# 20. Website Information

Display website hostname, protocol, domain, and actual scan time in a clean expandable card.

---

# 21. Risk Factors

Display findings as cards. Every finding must explain WHY it affected the score.

---

# 22. Trust Explanation

Add a **Why this score?** section showing the score contribution of URL analysis, domain signals, page content, HTTPS, AI assessment, and final score.

---

# 23. User Warning

For high-risk websites, display a clear warning telling users to avoid entering passwords, card information, OTPs, or personal information unless they trust the site.

Do not automatically block navigation in V1.

---

# 24. Scan History

Add optional local scan history showing hostname, score, risk level, and scan time.

Allow users to clear history. Store only necessary metadata locally.

---

# 25. Settings

Include:

- AI Detection toggle
- Automatic Scanning toggle
- Privacy explanation
- Clear Scan History
- Reset Settings
- Theme: Light / Dark / System

Do not make privacy claims that the implementation does not actually guarantee.

---

# 26. Privacy-First Design

The extension should:

- Minimize permissions
- Minimize collected data
- Avoid storing sensitive data
- Avoid sending unnecessary page content
- Never collect passwords
- Never collect cookies
- Never collect authentication tokens
- Avoid third-party tracking
- Clearly disclose external API usage
- Provide a privacy policy
- Allow users to disable AI

---

# 27. Security Requirements

Implement input validation, URL validation, API response validation, XSS protection, CSP compatibility, secure message passing, backend rate limiting, request timeouts, and limited retry strategies.

No hardcoded secrets.

Never use `eval()` or dynamically execute untrusted code.

---

# 28. Chrome Message Passing

Create strongly typed message contracts.

```ts
type ExtensionMessage =
  | {
      type: "SCAN_WEBSITE";
      payload: ScanRequest;
    }
  | {
      type: "GET_SETTINGS";
    }
  | {
      type: "UPDATE_AI_MODE";
      payload: {
        enabled: boolean;
      };
    };
```

Avoid `any`.

---

# 29. Error States

Create polished states for unsupported pages, network failures, AI unavailability, and unknown errors.

Chrome system pages and restricted pages should be handled gracefully.

---

# 30. Accessibility

Support keyboard navigation, focus states, ARIA labels, semantic HTML, screen readers, accessible contrast, and reduced-motion preferences.

---

# 31. Performance

Avoid unnecessary content scripts, continuous scanning unless enabled, expensive DOM traversal, and repeated scans.

Cache appropriate safe metadata, debounce repeated scans, cancel stale requests, and keep popup startup fast.

Target initial UI rendering below ~300 ms and rule-based scans below ~1 second where practical. Do not fake timings.

---

# 32. Testing

Use Vitest and React Testing Library.

Test rule engine cases, scoring, AI validation/failure handling, AI toggle, loading states, safe/suspicious results, errors, and scan history.

---

# 33. Backend

If AI/backend APIs are required, create a separate backend using Next.js API routes or Node.js + Express + TypeScript.

Responsibilities:

- AI requests
- API key protection
- Request validation
- Rate limiting
- Logging
- Error handling
- Response validation

Never bundle private API keys into the extension.

---

# 34. Environment Variables

Create `.env.example`:

```env
AI_PROVIDER=
AI_API_KEY=
API_BASE_URL=
```

Never commit real secrets.

---

# 35. Logging

Implement structured development logging without passwords, cookies, tokens, authorization headers, payment information, or complete webpage contents.

Production logging should be minimal.

---

# 36. TypeScript

Enable strict TypeScript and avoid `any`.

Use proper interfaces/types throughout the application.

---

# 37. UI Components

Create reusable components including:

- SecurityScore
- RiskBadge
- RiskFactorCard
- AIAnalysisCard
- AIModeToggle
- WebsiteInfo
- ScanProgress
- ScanButton
- RecommendationCard
- ScanHistory
- SettingsPanel
- EmptyState
- ErrorState

Keep business logic outside presentation components.

---

# 38. Animations

Use subtle score reveals, card entrances, toggle animations, scan progress, and risk badge transitions.

Respect `prefers-reduced-motion`.

---

# 39. Dark Mode

Support Light, Dark, and System themes and persist the setting.

---

# 40. Browser Compatibility

Target modern Chromium browsers supporting Manifest V3.

At minimum test Chrome and other Chromium-based browsers where practical.

---

# 41. README

Create a comprehensive README covering features, architecture, screenshots, installation, development, production builds, extension loading, environment variables, backend/AI setup, permissions, privacy, security, testing, deployment, and Chrome Web Store publishing.

---

# 42. Chrome Web Store Readiness

Verify:

- Manifest valid
- Icons included
- Permissions justified
- No unnecessary permissions
- No secrets in bundle
- Privacy policy prepared
- External services disclosed
- No misleading security claims
- No fake scan results
- Error handling implemented
- Production build works
- Extension works without AI
- AI failure does not break extension

---

# 43. Important Product Principle

ScamShield must NEVER claim:

> This website is definitely safe.

Prefer:

> No significant risk indicators detected.

Never claim:

> This is definitely a scam.

Prefer:

> Multiple indicators suggest this website may be unsafe.

Security detection is probabilistic.

---

# 44. Future Features

Architect for future additions such as:

- Google Safe Browsing
- VirusTotal
- URLScan
- WHOIS/domain intelligence
- Dangerous-site blocking
- Enterprise dashboard
- Team reporting
- Exportable scan reports
- PDF security reports
- QR code scanning
- Email/link scanning
- Automatic background protection
- Threat intelligence feeds
- Browser notifications

Do NOT implement all of these in V1.

---

# 45. Final Deliverable

Generate the complete working project.

Do NOT provide pseudocode or leave important functions as TODOs.

Provide:

1. Complete source code
2. Complete folder structure
3. `package.json`
4. `manifest.json`
5. Vite configuration
6. TypeScript configuration
7. ESLint configuration
8. Prettier configuration
9. React components
10. Chrome background service worker
11. Content script where required
12. Rule engine
13. Risk scoring engine
14. AI abstraction
15. Backend/API integration
16. Storage layer
17. Tests
18. README
19. `.env.example`
20. Production build instructions

---

# 46. Development Strategy

## Phase 1 — Foundation

- Vite
- React
- TypeScript
- Manifest V3
- Popup
- Side panel
- Chrome messaging
- Storage

## Phase 2 — Rule Engine

- URL analysis
- HTTPS detection
- Domain signals
- Page signals
- Redirect analysis
- Scoring

## Phase 3 — UI

- Security dashboard
- Score visualization
- Risk cards
- Scan progress
- History
- Settings

## Phase 4 — AI

- AI toggle
- Backend API
- Structured AI response
- Schema validation
- AI/rule result combination

## Phase 5 — Security

- Permissions review
- Input validation
- CSP
- Sensitive-data protection
- API security
- Rate limiting

## Phase 6 — Testing

- Unit tests
- Component tests
- Integration tests
- Edge cases

## Phase 7 — Production

- Optimized build
- Documentation
- Privacy policy
- Chrome Web Store readiness

---

# 47. Coding Quality Standard

Write code as if it will be reviewed by a senior engineer.

Prioritize maintainability, separation of concerns, type safety, testability, security, performance, accessibility, clean naming, reusable components, minimal dependencies, and clear error handling.

Do not over-engineer.

Every architectural decision should have a practical reason.

---

# 48. Start Now

Start by generating the project from scratch.

First show the complete folder structure.

Then implement the project file-by-file.

For every file:

1. Show the file path.
2. Provide the complete code.
3. Explain its responsibility briefly.
4. Ensure imports and exports are consistent.
5. Ensure the project can actually build.

At the end, provide:

```bash
npm install
npm run build
```

and the exact steps required to load the generated extension into Chrome.

The final result should be a **real, polished, production-oriented ScamShield Chrome extension**, not a toy project.
