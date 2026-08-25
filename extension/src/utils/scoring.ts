import { scoreToRiskLevel, type RiskFactor, type RiskLevel } from "@shared/index";
import type { DomainIdentity } from "@/utils/domainIdentity";

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

export interface CorrelationInput {
  domainIdentity?: DomainIdentity;
}

/**
 * Correlation rules (§13) — combinations of independent signals are far
 * stronger evidence than any single signal. Returns bonus deductions.
 */
export function evaluateCorrelations(
  factors: RiskFactor[],
  input: CorrelationInput,
): RiskFactor[] {
  const bonuses: RiskFactor[] = [];
  const ids = new Set(factors.map((f) => f.id));

  const hasCredentialForm =
    ids.has("page-login-form") || ids.has("page-payment-form");
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

  // §13 moderate: unknown domain + credential form + urgency
  if (!strongImpersonation && isUnrelatedOrWorse && hasCredentialForm && (hasUrgency || hasGiveaway)) {
    bonuses.push({
      id: "corr-unknown-credentials-pressure",
      title: "Unknown domain requesting credentials under pressure",
      description:
        "An unrelated domain collects credentials or payment details while applying urgency or reward pressure.",
      severity: "medium",
      points: 10,
      source: "rule",
    });
  }

  // §10 contextual TLD: suspicious TLD only matters alongside other evidence
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
  const correlations = evaluateCorrelations([...ruleFactors, ...aiFactors], correlationInput);
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
  for (const [key, def] of Object.entries(EVIDENCE_GROUPS) as Array<[EvidenceGroupKey, (typeof EVIDENCE_GROUPS)[EvidenceGroupKey]]>) {
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
