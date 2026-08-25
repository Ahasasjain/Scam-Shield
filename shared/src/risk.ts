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
