import type { DetectionRule, ScanContext } from "./ruleEngine";

/**
 * Dangerous-action detection (spec §3, §6, §14).
 *
 * These rules describe what a page ASKS for and WHERE it sends it. They are
 * structural observations only — no field values are ever read or stored.
 *
 * False-positive discipline (spec §3: "Do not flag every login/payment form
 * as malicious", §21 rule 8):
 * - A credential form ALONE is low severity. Hundreds of legitimate sites
 *   have login forms.
 * - Risk comes from CORRELATION: a credential form on a lookalike domain, or
 *   submitting off-domain, is what makes it phishing. That correlation lives
 *   in correlationEngine.ts, not here.
 */

/** §3 categories that legitimate web flows essentially never request. */
const NEVER_LEGITIMATE = new Set(["otp", "cvv"]);

type PageSignals = ScanContext["pageSignals"];

function hasKind(page: PageSignals, kind: string): boolean {
  return (page?.sensitiveKinds ?? []).includes(kind);
}

export const dangerousActionRules: DetectionRule[] = [
  {
    id: "page-otp-collection",
    name: "One-time password requested on a web page",
    description:
      "The page asks for a one-time password (OTP). Legitimate services deliver OTPs to your phone or email and ask you to type them into their native app — a browser form is a strong phishing indicator.",
    severity: "high",
    points: 26,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const matched = hasKind(pageSignals, "otp");
      return {
        matched,
        explanation: matched
          ? "A one-time-password (OTP) input is present on this page."
          : undefined,
      };
    },
  },
  {
    id: "page-cvv-collection",
    name: "Card security code (CVV) requested on a web page",
    description:
      "The page asks for a card security code (CVV/CVC). PCI-compliant merchants never collect CVV through a browser form, because it must not be stored or transmitted this way.",
    severity: "high",
    points: 26,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const matched = hasKind(pageSignals, "cvv");
      return {
        matched,
        explanation: matched
          ? "A card security code (CVV/CVC) input is present on this page."
          : undefined,
      };
    },
  },
  {
    id: "page-upi-collection",
    name: "UPI payment information requested",
    description:
      "The page asks for UPI identifiers or payment details. This is a common vector in Indian payment-refund and fake-KYC scams.",
    severity: "medium",
    points: 16,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const matched = hasKind(pageSignals, "upi");
      return {
        matched,
        explanation: matched
          ? "A UPI or virtual-payment-address input is present on this page."
          : undefined,
      };
    },
  },
  {
    id: "page-sensitive-personal-data",
    name: "Sensitive personal information requested",
    description:
      "The page asks for government identifiers, passport numbers, date of birth, or similar high-value personal data.",
    severity: "medium",
    points: 14,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const matched = hasKind(pageSignals, "personal");
      return {
        matched,
        explanation: matched
          ? "The page requests sensitive personal information (ID, passport, or date-of-birth style fields)."
          : undefined,
      };
    },
  },
  {
    id: "page-banking-credentials",
    name: "Banking credential fields present",
    description:
      "The page asks for banking identifiers such as an account number, routing number, IBAN, or net-banking PIN. This is weak supporting evidence on its own: legitimate bank logins and retailer billing pages do exactly this. It becomes meaningful only alongside an unrecognised domain, off-domain submission, or pressure language.",
    severity: "medium",
    points: 10,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const matched = hasKind(pageSignals, "banking");
      return {
        matched,
        explanation: matched
          ? "Banking credential fields (account, routing, IBAN, or net-banking PIN) are present."
          : undefined,
      };
    },
  },
  {
    id: "page-offdomain-sensitive-submit",
    name: "Sensitive form submits to an unrelated domain",
    description:
      "A form that collects credentials or payment details sends the data to a different registrable domain than the one serving the page. This is a much stronger signal than a sibling subdomain, which legitimate sites use routinely.",
    severity: "critical",
    points: 30,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const count = pageSignals?.offDomainSensitiveForms ?? 0;
      return {
        matched: count > 0,
        explanation:
          count > 0
            ? `${count} sensitive form(s) submit to an unrelated domain.`
            : undefined,
      };
    },
  },
  {
    id: "page-suspicious-download",
    name: "Suspicious download offered",
    description:
      "The page links to an executable, script, or archive file. Malware is commonly delivered as an attachment to a fake invoice, KYC update, or support offer.",
    severity: "medium",
    points: 14,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      const count = pageSignals?.suspiciousDownloadCount ?? 0;
      return {
        matched: count > 0,
        explanation:
          count > 0
            ? `${count} link(s) point to an executable, script, or archive file.`
            : undefined,
      };
    },
  },
  {
    id: "page-fake-verification",
    name: "Fake verification or KYC pressure",
    description:
      "The page uses fake KYC-verification or refund language — a hallmark of Indian payment-refund and fake-KYC scams.",
    severity: "medium",
    points: 14,
    category: "page",
    evaluate: ({ pageSignals }: ScanContext) => {
      // Counted into giveawayPatterns by the content script so the signal
      // reuses the existing deceptive-content evidence group and its cap.
      const count = pageSignals?.giveawayPatterns ?? 0;
      const matched = count >= 1;
      return {
        matched,
        explanation: matched
          ? "The page contains prize, refund, or fake-KYC verification language."
          : undefined,
      };
    },
  },
];

/** Exported for tests and for correlationEngine's category checks. */
export function isNeverLegitimateKind(kind: string): boolean {
  return NEVER_LEGITIMATE.has(kind);
}
