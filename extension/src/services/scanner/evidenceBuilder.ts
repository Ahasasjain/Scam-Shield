import type {
  DetectionCoverageV2,
  Evidence,
  EvidenceConfidence,
  EvidenceSource,
  EvidenceType,
  RiskFactor,
  RiskVerdict,
  SafeBrowsingStatus,
} from "@shared/index";
import type { ThreatIntelMatch } from "./threatIntelligenceAnalyzer";

/**
 * Evidence builder (spec §10, §20).
 *
 * Converts the scoring layer's `RiskFactor`s into the structured `Evidence`
 * model so that "why did ScamShield classify this website as dangerous?" can
 * be answered by inspecting the evidence alone.
 *
 * This module is deliberately pure: no I/O, no clock reads, no randomness.
 * Everything it needs is passed in, which is what makes it testable.
 */

/**
 * Factor id prefix → evidence type.
 *
 * NOTE: the `url-`/`page-` prefixes are load-bearing. `utils/scoring.ts#groupOf`
 * maps ids to capped evidence groups using the same prefixes, so a rule id
 * that is renamed here must be renamed there too (and in
 * `scanner/aiDecision.ts` if it should trigger an AI call).
 */
const ID_TYPE_OVERRIDES: ReadonlyArray<[string, EvidenceType]> = [
  ["url-lookalike-domain", "LOOKALIKE_DOMAIN"],
  ["url-lookalike-domain-strong", "LOOKALIKE_DOMAIN"],
  ["url-brand-in-subdomain", "BRAND_IMPERSONATION"],
  ["url-explicit-phishing-name", "BRAND_IMPERSONATION"],
  ["url-punycode", "LOOKALIKE_DOMAIN"],
  ["page-cross-origin-credentials", "CROSS_ORIGIN_FORM"],
  ["page-payment-cross-origin", "CROSS_ORIGIN_FORM"],
  ["page-offdomain-sensitive-submit", "CROSS_ORIGIN_FORM"],
  ["page-login-form", "CREDENTIAL_FORM"],
  ["page-password-over-http", "CREDENTIAL_FORM"],
  ["page-banking-credentials", "CREDENTIAL_FORM"],
  ["page-otp-collection", "CREDENTIAL_FORM"],
  ["page-payment-form", "PAYMENT_FORM"],
  ["page-cvv-collection", "PAYMENT_FORM"],
  ["page-upi-collection", "PAYMENT_FORM"],
  ["page-urgency-language", "URGENCY_LANGUAGE"],
  ["page-giveaway-patterns", "DECEPTIVE_CONTENT"],
  ["page-fake-warnings", "DECEPTIVE_CONTENT"],
  ["page-fake-verification", "DECEPTIVE_CONTENT"],
  ["page-suspicious-download", "SUSPICIOUS_DOWNLOAD"],
  ["threat-intel-match", "THREAT_INTEL_MATCH"],
];

export function evidenceTypeFor(factor: RiskFactor): EvidenceType {
  for (const [prefix, type] of ID_TYPE_OVERRIDES) {
    if (factor.id === prefix || factor.id.startsWith(`${prefix}-`)) return type;
  }
  if (factor.id.startsWith("url-")) return "UNSTRUCTURED_URL";
  if (factor.id.startsWith("https-")) return "WEAK_HTTPS";
  if (factor.id.startsWith("redirect-")) return "SUSPICIOUS_REDIRECT";
  if (factor.id.startsWith("page-")) return "UNCLASSIFIED";
  if (factor.id.startsWith("corr-")) return "UNCLASSIFIED";
  if (factor.id.startsWith("threat-")) return "THREAT_INTEL_MATCH";
  if (factor.id.startsWith("ai-")) return "UNCLASSIFIED";
  return "UNCLASSIFIED";
}

export function evidenceSourceFor(factor: RiskFactor): EvidenceSource {
  if (factor.id.startsWith("threat-")) return "threat_feed";
  if (factor.id.startsWith("corr-")) return "correlation";
  if (factor.id.startsWith("url-")) return "brand_intelligence";
  if (factor.id.startsWith("page-")) return "page_analysis";
  if (factor.id.startsWith("redirect-")) return "rule";
  if (factor.id.startsWith("https-")) return "rule";
  if (factor.id.startsWith("ai-")) return "ai";
  return "rule";
}

/**
 * Confidence is about how much the *evidence itself* can be trusted, which is
 * independent of severity. A "new domain" signal is genuinely weak evidence;
 * a confirmed Safe Browsing match is about as strong as evidence gets.
 */
const CONFIDENCE_OVERRIDES: ReadonlyArray<[string, EvidenceConfidence]> = [
  ["threat-intel-match", "confirmed"],
  ["page-cross-origin-credentials", "high"],
  ["page-payment-cross-origin", "high"],
  ["url-lookalike-domain-strong", "high"],
  ["url-lookalike-domain", "medium"],
  ["url-brand-in-subdomain", "medium"],
  ["url-explicit-phishing-name", "medium"],
  ["url-punycode", "high"],
  ["page-fake-warnings", "medium"],
  ["page-giveaway-patterns", "medium"],
  ["page-fake-verification", "medium"],
  ["page-otp-collection", "high"],
  ["page-cvv-collection", "high"],
  ["page-banking-credentials", "high"],
  ["page-offdomain-sensitive-submit", "high"],
  ["page-upi-collection", "medium"],
  ["page-sensitive-personal-data", "medium"],
  ["page-suspicious-download", "medium"],
  ["page-urgency-language", "low"],
  ["url-suspicious-tld", "low"],
  ["https-", "low"],
];

function confidenceFor(factor: RiskFactor): EvidenceConfidence {
  for (const [prefix, confidence] of CONFIDENCE_OVERRIDES) {
    if (factor.id === prefix || factor.id.startsWith(prefix)) return confidence;
  }
  // AI findings are model output: never treat them as high-confidence.
  if (factor.source === "ai") return "low";
  return "medium";
}

export function factorToEvidence(factor: RiskFactor): Evidence {
  return {
    id: factor.id,
    type: evidenceTypeFor(factor),
    severity: factor.severity,
    confidence: confidenceFor(factor),
    source: evidenceSourceFor(factor),
    title: factor.title,
    description: factor.description,
    metadata: { points: factor.points },
  };
}

/**
 * Remove duplicate evidence (spec §10: "avoid duplicate evidence" and
 * "avoid double-counting the same underlying signal").
 *
 * Two factors can describe one underlying observation (e.g. a lookalike
 * domain detected by both a URL rule and the brand engine). The first
 * occurrence wins because the deterministic rules are ordered most-specific
 * first, so the more explanatory item is retained.
 */
export function dedupeEvidence(evidence: Evidence[]): Evidence[] {
  const seen = new Set<string>();
  const out: Evidence[] = [];
  for (const item of evidence) {
    // Key on the *type* + normalised subject, not the id: two different rule
    // ids reporting the same category are the same underlying signal.
    const key = `${item.type}|${normaliseSubject(item.description)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function normaliseSubject(description: string): string {
  return description.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/**
 * Overall confidence in the verdict (spec §12).
 *
 * Determined by the strongest evidence present AND how complete the scan was.
 * A high score on partial coverage is low confidence, not high confidence.
 */
export function deriveConfidence(
  evidence: Evidence[],
  coverage: DetectionCoverageV2,
): EvidenceConfidence {
  const anyEvidence = evidence.length > 0;
  const sbMalicious =
    coverage.safeBrowsing === "KNOWN_MALICIOUS";

  if (sbMalicious) return "confirmed";

  // Nothing was found. Confidence that it is safe is only as high as the
  // completeness of the analysis.
  if (!anyEvidence) {
    const complete =
      coverage.page && coverage.threatIntel && coverage.reputation;
    return complete ? "medium" : "low";
  }

  if (!coverage.page || !coverage.threatIntel) return "low";

  const confirmed = evidence.some((e) => e.confidence === "confirmed");
  if (confirmed) return "high";
  const highCount = evidence.filter((e) => e.confidence === "high").length;
  if (highCount >= 2) return "high";
  if (highCount === 1) return "medium";
  return "low";
}

/**
 * Human-readable explanations of what could NOT be determined.
 *
 * Spec §12 requires incomplete analysis to be disclosed. An unexplained
 * partial scan is exactly how "unknown" silently degrades into "safe".
 */
export function deriveLimitations(
  coverage: DetectionCoverageV2,
  aiAvailable: boolean,
  threat: Pick<ThreatIntelMatch, "available" | "reason"> | undefined,
  redirectPermissionGranted = false,
): string[] {
  const limitations: string[] = [];

  switch (coverage.safeBrowsing) {
    case "LOOKUP_UNAVAILABLE":
      limitations.push(
        threat?.reason ??
          "Google Safe Browsing could not be reached, so this result does not include its threat database.",
      );
      break;
    case "UNKNOWN":
      limitations.push(
        "Google Safe Browsing returned an unrecognised response; its verdict is not included.",
      );
      break;
    case "NO_KNOWN_THREAT":
      // Important nuance worth surfacing: absence of a listing is not safety.
      limitations.push(
        "Google Safe Browsing lists no known threat for this site. That is not a guarantee that it is safe.",
      );
      break;
    case "KNOWN_MALICIOUS":
      break;
  }

  if (!coverage.page) {
    limitations.push(
      "Page contents could not be inspected (for example a browser or PDF page), so form and script behaviour was not analysed.",
    );
  }
  if (!coverage.redirects) {
    // Two distinct honest states share one coverage bit: never granted (fix
    // is the permission) vs granted but nothing recorded for this page load
    // (fix is a reload + rescan). Conflating them sends granted users on a
    // futile trip to Settings.
    limitations.push(
      redirectPermissionGranted
        ? "No redirect chain data was recorded for this page load — reload the page and scan again."
        : "The redirect chain was not analysed. Grant the optional webNavigation permission in Settings to enable it.",
    );
  }
  if (!coverage.reputation) {
    limitations.push(
      "Domain registration age could not be retrieved, so domain maturity is not reflected in this result.",
    );
  }
  if (!aiAvailable) {
    limitations.push(
      "AI analysis was unavailable; this verdict uses local and threat-intelligence evidence only.",
    );
  }

  return limitations;
}

/**
 * Whether the AI analyst ran (spec §9, §12).
 * - `degraded`  : evidence warranted an AI call but it could not complete.
 * - `deterministic-only` : AI was correctly not needed.
 * - `ai-enhanced`: AI contributed findings.
 */
export function deriveAnalysisMode(params: {
  aiRan: boolean;
  aiSucceeded: boolean;
  aiFindings: number;
  verdict: RiskVerdict;
}): "deterministic-only" | "ai-enhanced" | "degraded" {
  if (params.aiRan && params.aiSucceeded && params.aiFindings > 0) return "ai-enhanced";
  if (params.aiRan && !params.aiSucceeded) return "degraded";
  return "deterministic-only";
}

/** Builds the complete, explainable evidence list for a scan. */
export function buildEvidence(params: {
  factors: RiskFactor[];
  threat?: Pick<ThreatIntelMatch, "available" | "matched" | "source" | "threatType">;
  safeBrowsingStatus: SafeBrowsingStatus;
}): Evidence[] {
  const { factors, threat, safeBrowsingStatus } = params;
  const evidence = factors.map(factorToEvidence);

  // A confirmed provider match deserves its own top-level evidence item even
  // when the factor list already contains a threat factor, because the
  // provenance differs (Safe Browsing vs OpenPhish vs the curated list).
  if (
    threat?.available &&
    threat.matched &&
    safeBrowsingStatus === "KNOWN_MALICIOUS" &&
    !evidence.some((e) => e.type === "SAFE_BROWSING_MATCH")
  ) {
    evidence.unshift({
      id: "safe-browsing-match",
      type: "SAFE_BROWSING_MATCH",
      severity: "critical",
      confidence: "confirmed",
      source: "safe_browsing",
      title: "Google Safe Browsing flagged this site",
      description: `Google Safe Browsing lists this URL as ${
        threat.threatType ?? "malicious"
      }.`,
      metadata: { provider: threat.source ?? "googlesafebrowsing" },
    });
  }

  return dedupeEvidence(evidence);
}
