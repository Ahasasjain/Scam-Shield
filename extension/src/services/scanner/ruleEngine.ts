import type { DomainSignals, RiskFactor, Severity } from "@shared/index";
import type { DomainIdentity } from "@/utils/domainIdentity";

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
    suspiciousTld?: boolean;
  };
  /** Computed once by classifyDomain() — never re-derived inside rules. */
  domainIdentity?: DomainIdentity;
  pageSignals?: {
    hasLoginForm: boolean;
    hasPasswordFieldsOnHttp: boolean;
    hasPaymentForm: boolean;
    urgencyLanguageCount: number;
    giveawayPatterns: number;
    fakeSecurityWarnings: number;
    externalScriptOrigins: string[];
    formActions?: Array<{
      actionOrigin: string | null;
      isCrossOrigin: boolean;
      containsPassword: boolean;
      containsPaymentFields: boolean;
      /** §3 sensitive categories collected by this form. */
      kinds?: string[];
    }>;
    /** §3: union of sensitive categories present anywhere on the page. */
    sensitiveKinds?: string[];
    crossOriginSensitiveForms?: number;
    offDomainSensitiveForms?: number;
    suspiciousDownloadCount?: number;
  };
  redirectSignals?: {
    chainLength: number;
    crossOriginHops: number;
    finalUrl: string;
  };
  /**
   * RDAP domain-age lookup result. Reuses the shared discriminated union so
   * "lookup unavailable" can never be structurally confused with a successful
   * lookup with no age (invariant: unknown !== safe).
   */
  domainSignals?: DomainSignals;
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
