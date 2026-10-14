import type { DetectionRule } from "./ruleEngine";
export const domainRules: DetectionRule[] = [
  {
    id: "domain-newly-registered",
    name: "Recently registered domain",
    description:
      "The domain appears to have been registered recently. Domain age is supporting evidence only and is not proof of fraud.",
    severity: "medium",
    points: 8,
    category: "domain",
    evaluate: ({ domainSignals }) => ({
      matched:
        domainSignals?.available === true &&
        (domainSignals.domainAgeDays ?? Number.POSITIVE_INFINITY) < 30,
      explanation:
        domainSignals?.available === true
          ? `Domain age is approximately ${domainSignals.domainAgeDays ?? "unknown"} days.`
          : undefined,
    }),
  },
];
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
