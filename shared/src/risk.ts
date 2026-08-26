/**
 * Core risk types shared between the extension, the rule engine,
 * and the AI backend. Single source of truth — keep in sync via Zod
 * schemas in `schemas.ts`.
 */

export type Severity = "low" | "medium" | "high" | "critical";

export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export type FindingSource = "rule" | "ai";

/** A single explainable finding that contributed to the score. */
export interface RiskFactor {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  /** Points deducted from a perfect score of 100. Always >= 0. */
  points: number;
  source: FindingSource;
}

export type RiskCategory = "url" | "https" | "domain" | "page" | "redirect" | "ai";

/** Score bands per spec §13. */
export const SCORE_BANDS = {
  criticalMax: 29,
  highMax: 49,
  mediumMax: 69,
  lowMax: 84,
} as const;

export function scoreToRiskLevel(score: number): RiskLevel {
  if (score <= SCORE_BANDS.criticalMax) return "critical";
  if (score <= SCORE_BANDS.highMax) return "high";
  if (score <= SCORE_BANDS.mediumMax) return "medium";
  if (score <= SCORE_BANDS.lowMax) return "low";
  return "safe";
}

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  safe: "No significant indicators detected",
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
  critical: "Critical risk",
};

// ---------------------------------------------------------------------------
// Verdict system (spec §3, §29): unknown is NOT safe.
// ---------------------------------------------------------------------------

/**
 * Final verdict driven by evidence + confidence, not just arithmetic.
 * `unknown` means the system lacked evidence — never rendered as safe.
 */
export type RiskVerdict =
  | "known_safe"
  | "low_risk"
  | "suspicious"
  | "high_risk"
  | "dangerous"
  | "unknown";

export type Confidence = "high" | "medium" | "low" | "unknown";

/** Which analysis layers actually produced data for this scan (§29). */
export interface DetectionCoverage {
  url: boolean;
  domainIdentity: boolean;
  threatIntel: boolean;
  page: boolean;
  redirects: boolean;
  reputation: boolean;
}

export const VERDICT_LABELS: Record<RiskVerdict, string> = {
  known_safe: "Verified safe",
  low_risk: "Low risk",
  suspicious: "Suspicious website",
  high_risk: "High-risk website",
  dangerous: "Dangerous website",
  unknown: "Limited information",
};

export const VERDICT_RECOMMENDATIONS: Record<RiskVerdict, string> = {
  known_safe: "This domain is verified as the official organization it claims to be.",
  low_risk:
    "No significant indicators detected. As always, stay alert for unusual requests.",
  suspicious:
    "Do not enter passwords, card details, or personal information on this website.",
  high_risk: "Leave this website. Do not enter any information.",
  dangerous: "Leave this website immediately. It is a known phishing/threat.",
  unknown:
    "No known threat was found, but this website could not be fully verified. Proceed with caution.",
};
