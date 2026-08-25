import type { RiskFactor } from "@shared/index";
import { ruleToRiskFactor, type DetectionRule, type ScanContext } from "./ruleEngine";
import { urlRules } from "./urlAnalyzer";
import { httpsRules } from "./pageAnalyzer";
import { contentRules, redirectRules } from "./redirectAnalyzer";

/** All deterministic rules, grouped for the "Why this score?" view. */
export const ALL_RULES: readonly DetectionRule[] = [
  ...urlRules,
  ...httpsRules,
  ...contentRules,
  ...redirectRules,
];

export interface RuleEngineResult {
  factors: RiskFactor[];
  /** Rules that were skipped because their signals weren't collected. */
  skippedRuleIds: string[];
}

/**
 * Runs every rule against the scan context and returns explainable findings.
 * Deterministic: same context always produces same result.
 */
export function runRuleEngine(context: ScanContext): RuleEngineResult {
  const factors: RiskFactor[] = [];
  const skippedRuleIds: string[] = [];

  for (const rule of ALL_RULES) {
    // Page/redirect rules are skipped (not failed) when those signals
    // weren't collected — e.g. restricted pages.
    if (
      (rule.category === "page" && !context.pageSignals) ||
      (rule.category === "redirect" && !context.redirectSignals)
    ) {
      skippedRuleIds.push(rule.id);
      continue;
    }
    try {
      const result = rule.evaluate(context);
      if (result.matched) {
        factors.push(ruleToRiskFactor(rule, result));
      }
    } catch {
      // A failing rule must never break the whole scan; record and continue.
      skippedRuleIds.push(rule.id);
    }
  }

  return { factors, skippedRuleIds };
}
