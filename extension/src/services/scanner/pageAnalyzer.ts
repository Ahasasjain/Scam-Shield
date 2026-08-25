import type { DetectionRule } from "./ruleEngine";

/**
 * HTTPS / transport-security rules (spec §9).
 * Important: HTTPS only encrypts traffic — it does NOT mean a site is
 * legitimate, since phishing sites get free certificates too. These rules
 * are therefore low-severity and never treated as proof of safety.
 */
export const httpsRules: DetectionRule[] = [
  {
    id: "https-not-used",
    name: "No HTTPS (plain HTTP)",
    description:
      "The connection is not encrypted. Anything you enter can be intercepted. Note: HTTPS alone does not guarantee a site is legitimate.",
    severity: "medium",
    points: 12,
    category: "https",
    evaluate: ({ urlSignals }) => ({
      matched: !urlSignals.isHttps,
      explanation: `Site uses ${urlSignals.protocol}:// instead of https://.`,
    }),
  },
  {
    id: "page-password-over-http",
    name: "Password field on insecure page",
    description:
      "A password input is present on an unencrypted HTTP page — credentials could be intercepted in transit.",
    severity: "critical",
    points: 28,
    category: "https",
    evaluate: ({ pageSignals, urlSignals }) => ({
      matched: !urlSignals.isHttps && (pageSignals?.hasPasswordFieldsOnHttp ?? false),
      explanation: "Password inputs served over plain HTTP.",
    }),
  },
];

/**
 * Domain intelligence rules (spec §10). Real WHOIS/reputation data requires
 * a backend service; V1 reports honestly that this information is
 * unavailable rather than fabricating values.
 */
export const domainRules: DetectionRule[] = [];
