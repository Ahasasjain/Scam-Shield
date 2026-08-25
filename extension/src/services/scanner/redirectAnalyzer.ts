import type { DetectionRule } from "./ruleEngine";

/**
 * Page-content rules (spec §12). These evaluate signals collected by the
 * on-demand content script — never raw page contents.
 */
export const contentRules: DetectionRule[] = [
  {
    id: "page-login-form",
    name: "Login form detected",
    description:
      "The page contains a login form. Combined with other indicators this can suggest credential harvesting.",
    severity: "low",
    points: 5,
    category: "page",
    evaluate: ({ pageSignals }) => ({
      matched: pageSignals?.hasLoginForm ?? false,
      explanation: "A form with password input fields was found.",
    }),
  },
  {
    id: "page-cross-origin-credentials",
    name: "Credentials submit to a different website",
    description:
      "This page's password form sends data to a different domain than the one you are visiting — the hallmark of credential-harvesting phishing pages. Legitimate sites keep authentication on their own origin.",
    severity: "critical",
    points: 30,
    category: "page",
    evaluate: ({ pageSignals }) => {
      const crossOrigin = (pageSignals?.formActions ?? []).find(
        (f) => f.containsPassword && f.isCrossOrigin,
      );
      return {
        matched: crossOrigin !== undefined,
        explanation: crossOrigin
          ? `Password form submits to ${crossOrigin.actionOrigin ?? "another origin"}.`
          : undefined,
      };
    },
  },
  {
    id: "page-payment-cross-origin",
    name: "Payment details submit to a different website",
    description:
      "This page's payment form sends card data to a different domain than the one you are visiting.",
    severity: "high",
    points: 24,
    category: "page",
    evaluate: ({ pageSignals }) => {
      const crossOrigin = (pageSignals?.formActions ?? []).find(
        (f) => f.containsPaymentFields && f.isCrossOrigin && !f.containsPassword,
      );
      return {
        matched: crossOrigin !== undefined,
        explanation: crossOrigin
          ? `Payment form submits to ${crossOrigin.actionOrigin ?? "another origin"}.`
          : undefined,
      };
    },
  },
  {
    id: "page-payment-form",
    name: "Payment form detected",
    description:
      "The page requests card or payment information. Verify the site's legitimacy before entering payment details.",
    severity: "low",
    points: 5,
    category: "page",
    evaluate: ({ pageSignals }) => ({
      matched: pageSignals?.hasPaymentForm ?? false,
      explanation: "A payment/card input form was detected.",
    }),
  },
  {
    id: "page-urgency-language",
    name: "Urgency / pressure language",
    description:
      "Scam pages frequently pressure users with urgency ('act now', 'account suspended') to prevent careful review.",
    severity: "medium",
    points: 10,
    category: "page",
    evaluate: ({ pageSignals }) => ({
      matched: (pageSignals?.urgencyLanguageCount ?? 0) >= 2,
      explanation: `${pageSignals?.urgencyLanguageCount ?? 0} urgency phrases detected.`,
    }),
  },
  {
    id: "page-giveaway-patterns",
    name: "Giveaway / prize scam patterns",
    description:
      "Content promising prizes or rewards for personal data matches known scam patterns.",
    severity: "high",
    points: 16,
    category: "page",
    evaluate: ({ pageSignals }) => ({
      matched: (pageSignals?.giveawayPatterns ?? 0) >= 1,
      explanation: `${pageSignals?.giveawayPatterns ?? 0} giveaway/prize pattern(s) detected.`,
    }),
  },
  {
    id: "page-fake-warnings",
    name: "Fake security warning",
    description:
      "The page imitates browser or antivirus security warnings — a common scareware tactic.",
    severity: "critical",
    points: 26,
    category: "page",
    evaluate: ({ pageSignals }) => ({
      matched: (pageSignals?.fakeSecurityWarnings ?? 0) >= 1,
      explanation: `${pageSignals?.fakeSecurityWarnings ?? 0} fake security warning pattern(s) detected.`,
    }),
  },
];

/**
 * Redirect rules (spec §11). Redirects alone are not malicious —
 * many legitimate services use them. Only unusual chains are flagged.
 */
export const redirectRules: DetectionRule[] = [
  {
    id: "redirect-long-chain",
    name: "Multiple redirects",
    description: "The page required an unusually long chain of redirects.",
    severity: "low",
    points: 6,
    category: "redirect",
    evaluate: ({ redirectSignals }) => ({
      matched: (redirectSignals?.chainLength ?? 0) >= 4,
      explanation: `Redirect chain length: ${redirectSignals?.chainLength ?? 0}.`,
    }),
  },
  {
    id: "redirect-cross-origin",
    name: "Cross-origin redirect hops",
    description:
      "The redirect chain crosses between unrelated domains before landing on the final page.",
    severity: "medium",
    points: 12,
    category: "redirect",
    evaluate: ({ redirectSignals }) => ({
      matched: (redirectSignals?.crossOriginHops ?? 0) >= 2,
      explanation: `${redirectSignals?.crossOriginHops ?? 0} cross-origin hops detected.`,
    }),
  },
];
