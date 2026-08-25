import { scoreToRiskLevel, type RiskFactor, type RiskLevel } from "@shared/index";

export interface ScoreBreakdownEntry {
  category: string;
  label: string;
  points: number;
}

export interface ScoreResult {
  score: number;
  riskLevel: RiskLevel;
  breakdown: ScoreBreakdownEntry[];
}

const CATEGORY_LABELS: Record<string, string> = {
  url: "URL analysis",
  https: "HTTPS & transport",
  domain: "Domain signals",
  page: "Page content",
  redirect: "Redirects",
  ai: "AI assessment",
};

function clampScore(raw: number): number {
  return Math.max(0, Math.min(100, Math.round(raw)));
}

/**
 * Transparent scoring (spec §13):
 * - Start at 100 ("no indicators").
 * - Subtract each finding's points.
 * - AI findings can reduce the score further but a floor of 10 is kept when
 *   only AI findings exist — AI never fully overrides deterministic signals.
 *
 * Every deduction is returned in `breakdown` so the UI can explain exactly
 * why the score is what it is.
 */
export function calculateScore(
  ruleFactors: RiskFactor[],
  aiFactors: RiskFactor[] = [],
): ScoreResult {
  const allFactors = [...ruleFactors, ...aiFactors];
  const totalDeduction = allFactors.reduce((sum, f) => sum + f.points, 0);
  const score = clampScore(100 - totalDeduction);

  const byCategory = new Map<string, number>();
  for (const factor of allFactors) {
    const category = factor.id.startsWith("ai-") ? "ai" : categoryOf(factor.id);
    byCategory.set(category, (byCategory.get(category) ?? 0) + factor.points);
  }

  const breakdown: ScoreBreakdownEntry[] = Object.keys(CATEGORY_LABELS)
    .filter((c) => byCategory.has(c))
    .map((category) => ({
      category,
      label: CATEGORY_LABELS[category] ?? category,
      points: byCategory.get(category) ?? 0,
    }));

  return { score, riskLevel: scoreToRiskLevel(score), breakdown };
}

function categoryOf(ruleId: string): string {
  if (ruleId.startsWith("url-")) return "url";
  if (ruleId.startsWith("https-") || ruleId === "page-password-over-http")
    return "https";
  if (ruleId.startsWith("page-")) return "page";
  if (ruleId.startsWith("redirect-")) return "redirect";
  if (ruleId.startsWith("domain-")) return "domain";
  return "url";
}
