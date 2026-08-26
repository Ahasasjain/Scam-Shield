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

export function evaluateCorrelations(
  factors: RiskFactor[],
  input: CorrelationInput,
): RiskFactor[] {
  const bonuses: RiskFactor[] = [];
  const ids = new Set(factors.map((f) => f.id));

  const hasCredentialForm = ids.has("page-login-form") || ids.has("page-payment-form");
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
      return "dangerous";
    }
    return "high_risk";
  }

  const ids = new Set(factorIds ?? []);
  const relationship = domainIdentity?.relationship;
  const official = relationship === "official" || relationship === "trusted-subdomain";

  // Evidence-based escalations independent of arithmetic score.
  if (ids.has("page-cross-origin-credentials")) {
    return score <= 49 ? "dangerous" : "high_risk";
  }

  if (relationship === "lookalike" || relationship === "brand-in-subdomain") {
    if (score <= 49) return "dangerous";
    return "suspicious";
  }

  // Generic phishing pattern: unknown domain + credentials + pressure signals
  // (correlation bonuses present) → at least suspicious even at high scores.
  const genericPhishing =
    (ids.has("corr-unknown-credentials-pressure") ||
      ids.has("corr-weak-url-credentials")) &&
    (ids.has("page-login-form") || ids.has("page-payment-form"));
  if (genericPhishing && score <= 84) {
    return "suspicious";
  }

  if (score <= 29) return "dangerous";
  if (score <= 49) return "high_risk";
  if (score <= 69) return "suspicious";

  // High scores: official domains are known_safe; everything else depends
  // on coverage — insufficient evidence is UNKNOWN, never safe (§3).
  if (official) return "known_safe";
  if (!pageAnalyzed) return "unknown";
  return "low_risk";
}
