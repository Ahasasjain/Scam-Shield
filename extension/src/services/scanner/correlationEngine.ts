import type { RiskFactor, RiskVerdict } from "@shared/index";
import type { DomainIdentity } from "@/utils/domainIdentity";
import type { ThreatIntelMatch } from "./threatIntelligenceAnalyzer";

/**
 * Correlation engine (spec §21) + final verdict derivation (§3, §30).
 *
 * Combinations of independent signals are far stronger evidence than any
 * single signal. Bonuses are explicit and bounded — underlying points are
 * never double-counted wholesale.
 */

export interface CorrelationInput {
  domainIdentity?: DomainIdentity;
  threatMatch?: { available: boolean; matched: boolean };
}

/**
 * Signals strong enough to escalate an allowlisted official domain on their own.
 *
 * Spec §4 / §11 / §21 rule 8: weak structural evidence and a plain login form
 * are SUPPORTING evidence, never decisive. Real-world false positives proved
 * why: an Amazon OpenID sign-in URL is ~380 characters and percent-encoded by
 * design, so "excessive URL length" + "URL encoding abuse" + "login form"
 * summed past the SUSPICIOUS band on amazon.in — an allowlisted official
 * domain. Long URLs and percent-encoding are likewise routine on YouTube,
 * Google search, and any redirect-based login flow.
 *
 * A domain on the brand allowlist therefore cannot be escalated above
 * LOW_RISK by structural noise alone. Genuine danger on an "official" domain
 * still escalates, because it arrives via one of these ids.
 */
const SUBSTANTIVE_FACTOR_IDS: ReadonlySet<string> = new Set([
  "threat-intel-match",
  "page-cross-origin-credentials",
  "page-payment-cross-origin",
  "page-offdomain-sensitive-submit",
  // OTP and CVV are never collected in a legitimate browser form (spec §3).
  "page-otp-collection",
  "page-cvv-collection",
  "corr-impersonation-otp",
  "corr-upi-refund-scam",
  "corr-unknown-credentials-pressure",
]);

/**
 * A score at or above this means at most weak supporting signals fired, so an
 * official domain with no substantive evidence can still reach SAFE.
 */
const OFFICIAL_CLEAN_SCORE = 90;

export function evaluateCorrelations(
  factors: RiskFactor[],
  input: CorrelationInput,
): RiskFactor[] {
  const bonuses: RiskFactor[] = [];
  const ids = new Set(factors.map((f) => f.id));

  // §3: a page that asks for an OTP, a CVV, or banking credentials is
  // collecting high-value secrets regardless of whether it is a "login form".
  const hasSensitiveCollection =
    ids.has("page-login-form") ||
    ids.has("page-payment-form") ||
    ids.has("page-otp-collection") ||
    ids.has("page-cvv-collection") ||
    ids.has("page-banking-credentials");
  const hasCredentialForm = hasSensitiveCollection;
  const hasPaymentForm =
    ids.has("page-payment-form") ||
    ids.has("page-cvv-collection") ||
    ids.has("page-upi-collection");
  const hasUrgency = ids.has("page-urgency-language");
  const hasFakeWarning = ids.has("page-fake-warnings");
  const hasGiveaway = ids.has("page-giveaway-patterns");

  const strongImpersonation =
    ids.has("url-lookalike-domain-strong") ||
    ids.has("url-brand-in-subdomain") ||
    ids.has("url-lookalike-domain");
  const relationship = input.domainIdentity?.relationship;
  const isUnrelatedOrWorse =
    relationship !== undefined &&
    relationship !== "official" &&
    relationship !== "trusted-subdomain";

  // §13 strong: impersonation + credential collection
  if (strongImpersonation && hasCredentialForm) {
    bonuses.push({
      id: "corr-impersonation-credentials",
      title: "Impersonation combined with credential collection",
      description:
        "This page both imitates a well-known brand AND asks for credentials or payment details — a high-confidence phishing pattern.",
      severity: "high",
      points: 15,
      source: "rule",
    });
  }

  // §13 critical: impersonation + credentials + urgency
  if (strongImpersonation && hasCredentialForm && hasUrgency) {
    bonuses.push({
      id: "corr-impersonation-credentials-urgency",
      title: "Deceptive pattern: impersonation + credentials + urgency",
      description:
        "Brand impersonation, credential/payment collection, and urgency pressure appear together — a critical phishing combination.",
      severity: "critical",
      points: 20,
      source: "rule",
    });
  }

  // §13 critical: impersonation + fake security warning
  if (strongImpersonation && hasFakeWarning) {
    bonuses.push({
      id: "corr-impersonation-fakewarning",
      title: "Impersonation combined with fake security warning",
      description:
        "The page imitates a known brand and displays fake security warnings — classic scareware/phishing.",
      severity: "critical",
      points: 18,
      source: "rule",
    });
  }

  // Generic phishing (§21): unrelated domain + credentials + ANY pressure/
  // deception signal. This is what makes non-brand phishing score risky.
  const deceptionSignals = [hasUrgency, hasFakeWarning, hasGiveaway].filter(
    Boolean,
  ).length;
  const weakUrlSignals =
    ids.has("url-suspicious-tld") ||
    ids.has("url-hyphen-overload") ||
    ids.has("url-nested-subdomains") ||
    ids.has("url-excessive-length") ||
    ids.has("url-encoded-chars") ||
    ids.has("url-punycode");

  if (
    isUnrelatedOrWorse &&
    hasCredentialForm &&
    (deceptionSignals >= 1 || ids.has("page-cross-origin-credentials"))
  ) {
    bonuses.push({
      id: "corr-unknown-credentials-pressure",
      title: "Unknown website collecting credentials under pressure",
      description:
        "An unrecognized domain collects credentials or payment details while applying urgency, rewards, or deceptive content — a common phishing pattern.",
      severity: "medium",
      points: 12,
      source: "rule",
    });
  }

  // Weak URL cluster on a credential page: still meaningful in aggregate.
  if (isUnrelatedOrWorse && hasCredentialForm && weakUrlSignals) {
    bonuses.push({
      id: "corr-weak-url-credentials",
      title: "Suspicious URL structure on a credential page",
      description:
        "Multiple structural URL anomalies appear together with a login or payment form.",
      severity: "low",
      points: 6,
      source: "rule",
    });
  }

  // §10 contextual TLD.
  if (ids.has("url-suspicious-tld") && (hasCredentialForm || strongImpersonation)) {
    bonuses.push({
      id: "corr-suspicious-tld-context",
      title: "Uncommon TLD combined with sensitive-page indicators",
      description:
        "An uncommon top-level domain appears together with credential collection or impersonation evidence.",
      severity: "low",
      points: 5,
      source: "rule",
    });
  }

  // §3: OTP + any impersonation is a critical combination. Services ask users
  // to type OTPs into native apps, never into a browser form on a
  // brand-impersonating site.
  if (ids.has("page-otp-collection") && strongImpersonation) {
    bonuses.push({
      id: "corr-impersonation-otp",
      title: "Impersonation combined with an OTP request",
      description:
        "The page imitates a known brand and asks for a one-time password. Legitimate services never collect OTPs through a web form.",
      severity: "critical",
      points: 22,
      source: "rule",
    });
  }

  // §3/§14: India-specific payment-scam cluster — UPI/KYC language plus a
  // payment form on an unknown domain.
  const upiScam =
    (ids.has("page-upi-collection") || ids.has("page-fake-verification")) &&
    hasPaymentForm &&
    isUnrelatedOrWorse;
  if (upiScam) {
    bonuses.push({
      id: "corr-upi-refund-scam",
      title: "Payment or KYC scam pattern",
      description:
        "An unrecognized site combines UPI or fake-KYC verification language with a payment form — a common refund-fraud pattern.",
      severity: "high",
      points: 20,
      source: "rule",
    });
  }

  return bonuses;
}

// ---------------------------------------------------------------------------
// Final verdict derivation (§3, §30): evidence + confidence over arithmetic.
// ---------------------------------------------------------------------------

export interface VerdictInput {
  score: number;
  threatMatch?: ThreatIntelMatch;
  domainIdentity?: DomainIdentity;
  /** True when page analysis produced data. */
  pageAnalyzed: boolean;
  /** All rule + correlation + AI factor ids — used for evidence-based verdicts. */
  factorIds?: string[];
}

export function deriveVerdict(input: VerdictInput): RiskVerdict {
  const { score, threatMatch, domainIdentity, pageAnalyzed, factorIds } = input;

  // §6: confirmed threat intel overrides everything.
  if (threatMatch?.available && threatMatch.matched) {
    if (threatMatch.confidence === "confirmed" || threatMatch.confidence === "high") {
      return "DANGEROUS";
    }
    return "HIGH_RISK";
  }

  const ids = new Set(factorIds ?? []);
  const relationship = domainIdentity?.relationship;
  const official = relationship === "official" || relationship === "trusted-subdomain";

  // Evidence-based escalations independent of arithmetic score.
  if (ids.has("page-cross-origin-credentials")) {
    return score <= 49 ? "DANGEROUS" : "HIGH_RISK";
  }

  // §3: credentials or payment details leaving for an unrelated registrable
  // domain is a deterministic, hard-to-explain-away pattern.
  if (ids.has("page-offdomain-sensitive-submit")) {
    return score <= 49 ? "DANGEROUS" : "HIGH_RISK";
  }

  // §3: an OTP request is a high-severity signal on its own, but only
  // escalates to HIGH_RISK when the page is not an official destination.
  if (ids.has("page-otp-collection") && !official) {
    return score <= 49 ? "DANGEROUS" : "HIGH_RISK";
  }

  if (relationship === "lookalike" || relationship === "brand-in-subdomain") {
    if (score <= 49) return "DANGEROUS";
    return "SUSPICIOUS";
  }

  if (ids.has("url-explicit-phishing-name")) return "SUSPICIOUS";

  // Generic phishing pattern: unknown domain + credentials + pressure signals
  // (correlation bonuses present) → at least suspicious even at high scores.
  const genericPhishing =
    (ids.has("corr-unknown-credentials-pressure") ||
      ids.has("corr-weak-url-credentials")) &&
    (ids.has("page-login-form") || ids.has("page-payment-form"));
  if (genericPhishing && score <= 84) {
    return "SUSPICIOUS";
  }

  // An allowlisted official domain with only weak structural evidence can
  // never be escalated by arithmetic. Official-brand domains legitimately
  // produce long, percent-encoded, parameter-heavy URLs (Amazon OpenID
  // sign-in, Google search, YouTube playlists) and legitimately contain login
  // forms and billing fields. Requiring substantive evidence here is what
  // keeps spec §21 rule 8 (minimise false positives) honest.
  const hasSubstantiveEvidence = [...ids].some((id) =>
    SUBSTANTIVE_FACTOR_IDS.has(id),
  );
  if (official && !hasSubstantiveEvidence && score < OFFICIAL_CLEAN_SCORE) {
    // Structural noise on an allowlisted domain: real, but never enough on its
    // own. Falls back to LOW_RISK (or UNKNOWN when the page was not analysed)
    // instead of being allowed into the SUSPICIOUS band.
    return pageAnalyzed ? "LOW_RISK" : "UNKNOWN";
  }

  if (score <= 29) return "DANGEROUS";
  if (score <= 49) return "HIGH_RISK";
  if (score <= 69) return "SUSPICIOUS";

  // A provider no-match means no known threat, not proof of safety. Keep SAFE
  // reserved for an official domain when threat intelligence is unavailable
  // only because this scan has no provider configured; a clean provider
  // response remains LOW_RISK.
  //
  // SAFE additionally requires a near-clean score. Being on an official domain
  // does not make an active finding disappear: an official-looking page that
  // still asks for an OTP has real indicators, so it must not render as
  // "Verified safe". A score of 90+ means at most weak supporting signals.
  if (official && threatMatch?.status !== "NO_KNOWN_THREAT" && score >= 90) {
    return "SAFE";
  }
  if (!pageAnalyzed) return "UNKNOWN";
  return "LOW_RISK";
}
