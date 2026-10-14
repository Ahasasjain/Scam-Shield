import type { RiskFactor } from "@shared/index";
import type { ThreatIntelMatch } from "./threatIntelligenceAnalyzer";

export interface AiDecision {
  needed: boolean;
  reasons: string[];
}

/**
 * AI is an expensive, fallible enrichment step. These are meaningful local
 * signals that justify asking Groq for a second opinion. Weak or normal
 * website properties intentionally do not trigger AI by themselves.
 */
const AI_TRIGGER_IDS = new Map<string, string>([
  ["url-lookalike-domain", "lookalike domain"],
  ["url-lookalike-domain-strong", "near-exact lookalike domain"],
  ["url-brand-in-subdomain", "brand impersonation in a subdomain"],
  ["url-explicit-phishing-name", "phishing-related domain name"],
  ["page-cross-origin-credentials", "cross-origin credential submission"],
  ["page-payment-cross-origin", "cross-origin payment submission"],
  ["page-offdomain-sensitive-submit", "sensitive form submitting off-domain"],
  ["page-otp-collection", "one-time password request"],
  ["page-cvv-collection", "card security code request"],
  ["page-banking-credentials", "banking credential request"],
  ["page-fake-verification", "fake KYC or refund verification"],
  ["page-fake-warnings", "fake security warning"],
  ["page-giveaway-patterns", "giveaway or prize scam pattern"],
  ["page-urgency-language", "strong urgency or pressure language"],
  ["redirect-long-chain", "suspicious redirect chain"],
  ["redirect-cross-origin", "cross-origin redirects"],
  ["corr-impersonation-credentials", "impersonation with credential collection"],
  [
    "corr-impersonation-credentials-urgency",
    "impersonation with credentials and urgency",
  ],
  ["corr-impersonation-fakewarning", "impersonation with fake warning"],
  [
    "corr-unknown-credentials-pressure",
    "unknown site collecting credentials under pressure",
  ],
]);

export function decideAiNeed(
  factors: RiskFactor[],
  threatMatch?: Pick<ThreatIntelMatch, "available" | "matched">,
  force = false,
): AiDecision {
  // Confirmed threat intelligence is authoritative; AI cannot improve or
  // downgrade that verdict, so do not spend a provider request on it.
  if (threatMatch?.available && threatMatch.matched) {
    return { needed: false, reasons: ["confirmed threat intelligence"] };
  }

  if (force) return { needed: true, reasons: ["temporary AI test mode"] };

  const reasons = [
    ...new Set(
      factors
        .map((factor) => AI_TRIGGER_IDS.get(factor.id))
        .filter((reason): reason is string => reason !== undefined),
    ),
  ];
  return { needed: reasons.length > 0, reasons };
}
