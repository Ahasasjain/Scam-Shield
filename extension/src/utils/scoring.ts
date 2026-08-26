import { scoreToRiskLevel, type RiskFactor, type RiskLevel } from "@shared/index";
import {
  evaluateCorrelations,
  type CorrelationInput,
} from "@/services/scanner/correlationEngine";

export { evaluateCorrelations } from "@/services/scanner/correlationEngine";

export interface ScoreBreakdownEntry {
  category: string;
  label: string;
  points: number;
  /** True when this category hit its evidence cap. */
  capped?: boolean;
}

export interface ScoreResult {
  score: number;
  riskLevel: RiskLevel;
  breakdown: ScoreBreakdownEntry[];
}

/**
 * Evidence groups (§12) — related signals share a cap so weak URL
 * characteristics can't accumulate into a high-risk verdict on their own.
 */
const EVIDENCE_GROUPS = {
  threatIntel: { label: "Threat intelligence", cap: 100 },
  domainIdentity: { label: "Domain identity", cap: 40 },
  brandImpersonation: { label: "Brand impersonation", cap: 35 },
  urlStructure: { label: "URL structure", cap: 15 },
  pageContent: { label: "Page content", cap: 30 },
  transport: { label: "HTTPS & transport", cap: 20 },
  redirects: { label: "Redirects", cap: 15 },
} as const;

type EvidenceGroupKey = keyof typeof EVIDENCE_GROUPS;

/** Maps rule ids to their evidence group. */
function groupOf(factorId: string): EvidenceGroupKey {
  if (factorId.startsWith("threat-")) return "threatIntel";
  if (
    factorId === "url-brand-in-subdomain" ||
    factorId === "url-lookalike-domain" ||
    factorId === "url-lookalike-domain-strong"
  ) {
    return "brandImpersonation";
  }
  if (factorId.startsWith("url-")) return "urlStructure";
  if (factorId.startsWith("https-") || factorId === "page-password-over-http")
    return "transport";
  if (factorId.startsWith("page-")) return "pageContent";
  if (factorId.startsWith("redirect-")) return "redirects";
  return "domainIdentity";
}

function clampScore(raw: number): number {
  return Math.max(0, Math.min(100, Math.round(raw)));
}

/**
 * Transparent scoring (§15):
 * - Start at 100 ("no indicators").
 * - Sum deductions per evidence group; each group is CAPPED so weak
 *   structural signals cannot overwhelm domain identity or page evidence.
 * - Add correlation bonuses for deceptive signal combinations.
 * - Clamp to [0, 100]. Deterministic and fully explainable.
 *
 * The score is an INDICATOR score, not a probability of safety/fraud.
 */
export function calculateScore(
  ruleFactors: RiskFactor[],
  aiFactors: RiskFactor[] = [],
  correlationInput: CorrelationInput = {},
): ScoreResult {
  const correlations = evaluateCorrelations(
    [...ruleFactors, ...aiFactors],
    correlationInput,
  );
  const allFactors = [...ruleFactors, ...aiFactors, ...correlations];

  // Per-group raw sums.
  const groupSums = new Map<EvidenceGroupKey, number>();
  for (const factor of allFactors) {
    const group = groupOf(factor.id);
    groupSums.set(group, (groupSums.get(group) ?? 0) + factor.points);
  }

  // Apply caps per group.
  let totalRisk = 0;
  const breakdown: ScoreBreakdownEntry[] = [];
  for (const [key, def] of Object.entries(EVIDENCE_GROUPS) as Array<
    [EvidenceGroupKey, (typeof EVIDENCE_GROUPS)[EvidenceGroupKey]]
  >) {
    const raw = groupSums.get(key) ?? 0;
    if (raw === 0) continue;
    const cappedValue = Math.min(raw, def.cap);
    totalRisk += cappedValue;
    breakdown.push({
      category: key,
      label: def.label,
      points: cappedValue,
      capped: raw > def.cap,
    });
  }

  const score = clampScore(100 - totalRisk);
  breakdown.sort((a, b) => b.points - a.points);

  return { score, riskLevel: scoreToRiskLevel(score), breakdown };
}
