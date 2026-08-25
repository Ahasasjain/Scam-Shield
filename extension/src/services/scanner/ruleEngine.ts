import type { RiskFactor, Severity } from "@shared/index";

/**
 * Detection rule contract (spec §8). Every rule is deterministic and
 * explainable: it either matches with evidence or it doesn't.
 */
export interface ScanContext {
  url: string;
  urlSignals: {
    protocol: string;
    hostname: string;
    registrableDomain: string;
    isHttps: boolean;
    isIpHost: boolean;
    urlLength: number;
    subdomainDepth: number;
    hyphenCount: number;
    hasPunycode: boolean;
    tld: string;
    pathLength: number;
  };
  pageSignals?: {
    hasLoginForm: boolean;
    hasPasswordFieldsOnHttp: boolean;
    hasPaymentForm: boolean;
    urgencyLanguageCount: number;
    giveawayPatterns: number;
    fakeSecurityWarnings: number;
    externalScriptOrigins: string[];
  };
  redirectSignals?: {
    chainLength: number;
    crossOriginHops: number;
    finalUrl: string;
  };
  domainSignals?: {
    available: false;
    reason: string;
  };
}

export interface RuleResult {
  matched: boolean;
  /** Human-readable evidence explaining WHY the rule matched. */
  explanation?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  /** Points deducted when the rule matches. */
  points: number;
  category: "url" | "https" | "domain" | "page" | "redirect";
  evaluate(context: ScanContext): RuleResult;
}

export function ruleToRiskFactor(rule: DetectionRule, result: RuleResult): RiskFactor {
  return {
    id: rule.id,
    title: rule.name,
    description: result.explanation ?? rule.description,
    severity: rule.severity,
    points: rule.points,
    source: "rule",
  };
}
