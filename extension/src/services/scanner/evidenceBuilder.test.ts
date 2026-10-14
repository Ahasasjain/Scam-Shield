import { describe, expect, it } from "vitest";
import type { DetectionCoverageV2, RiskFactor } from "@shared/index";
import {
  buildEvidence,
  dedupeEvidence,
  deriveAnalysisMode,
  deriveConfidence,
  deriveLimitations,
  evidenceSourceFor,
  evidenceTypeFor,
  factorToEvidence,
} from "./evidenceBuilder";

/**
 * Spec §10 / §12 coverage for the evidence model.
 *
 * The load-bearing properties are: evidence is explainable, provenance is
 * preserved, duplicates are collapsed, and incomplete coverage is disclosed
 * rather than silently treated as a clean result.
 */

const FULL_COVERAGE: DetectionCoverageV2 = {
  url: true,
  domainIdentity: true,
  threatIntel: true,
  page: true,
  redirects: true,
  reputation: true,
  safeBrowsing: "NO_KNOWN_THREAT",
};

function factor(partial: Partial<RiskFactor> & { id: string }): RiskFactor {
  return {
    title: "Title",
    description: "Description",
    severity: "medium",
    points: 10,
    source: "rule",
    ...partial,
  };
}

describe("evidence classification", () => {
  it("maps lookalike-domain rule ids to LOOKALIKE_DOMAIN", () => {
    expect(
      evidenceTypeFor(factor({ id: "url-lookalike-domain-strong" })),
    ).toBe("LOOKALIKE_DOMAIN");
    expect(evidenceTypeFor(factor({ id: "url-punycode" }))).toBe("LOOKALIKE_DOMAIN");
  });

  it("does not flag a brand name in the path as impersonation evidence", () => {
    // §4 critical rule: a brand mentioned in a URL alone is not phishing
    // evidence. A generic structural signal must stay UNSTRUCTURED_URL.
    expect(evidenceTypeFor(factor({ id: "url-excessive-length" }))).toBe(
      "UNSTRUCTURED_URL",
    );
  });

  it("maps cross-origin credential submission to CROSS_ORIGIN_FORM", () => {
    expect(
      evidenceTypeFor(factor({ id: "page-cross-origin-credentials" })),
    ).toBe("CROSS_ORIGIN_FORM");
  });

  it("preserves provider provenance in the evidence source", () => {
    expect(evidenceSourceFor(factor({ id: "threat-intel-match" }))).toBe(
      "threat_feed",
    );
    expect(evidenceSourceFor(factor({ id: "corr-impersonation-credentials" }))).toBe(
      "correlation",
    );
    expect(evidenceSourceFor(factor({ id: "ai-something", source: "ai" }))).toBe(
      "ai",
    );
  });

  it("never rates AI output as high confidence", () => {
    const ai = factorToEvidence(
      factor({ id: "ai-brand_impersonation", source: "ai", severity: "critical" }),
    );
    expect(ai.confidence).toBe("low");
  });
});

describe("dedupeEvidence", () => {
  it("collapses two rules reporting the same underlying signal", () => {
    const a = factorToEvidence(
      factor({ id: "url-lookalike-domain", description: "Domain mimics PayPal" }),
    );
    const b = factorToEvidence(
      factor({ id: "url-lookalike-domain-alt", description: "Domain mimics PayPal" }),
    );

    const deduped = dedupeEvidence([a, b]);

    expect(deduped).toHaveLength(1);
    // The first (most specific) item is retained.
    expect(deduped[0]?.id).toBe("url-lookalike-domain");
  });

  it("keeps genuinely different evidence", () => {
    const a = factorToEvidence(factor({ id: "page-login-form", description: "Login form" }));
    const b = factorToEvidence(
      factor({ id: "page-payment-form", description: "Payment form" }),
    );

    expect(dedupeEvidence([a, b])).toHaveLength(2);
  });
});

describe("deriveConfidence", () => {
  it("is confirmed for a Safe Browsing malicious hit", () => {
    expect(
      deriveConfidence([], { ...FULL_COVERAGE, safeBrowsing: "KNOWN_MALICIOUS" }),
    ).toBe("confirmed");
  });

  it("is low when the page could not be analysed", () => {
    const evidence = [factorToEvidence(factor({ id: "url-lookalike-domain-strong" }))];
    expect(
      deriveConfidence(evidence, { ...FULL_COVERAGE, page: false }),
    ).toBe("low");
  });

  it("is low when threat intelligence was unavailable", () => {
    const evidence = [factorToEvidence(factor({ id: "url-lookalike-domain-strong" }))];
    expect(
      deriveConfidence(evidence, { ...FULL_COVERAGE, threatIntel: false }),
    ).toBe("low");
  });

  it("does not claim high confidence on a complete scan with no findings", () => {
    // "Nothing found" on a complete scan is medium confidence, never "confirmed".
    expect(deriveConfidence([], FULL_COVERAGE)).toBe("medium");
  });
});

describe("deriveLimitations", () => {
  it("discloses a Safe Browsing outage", () => {
    const limits = deriveLimitations(
      { ...FULL_COVERAGE, safeBrowsing: "LOOKUP_UNAVAILABLE" },
      true,
      { available: false, reason: "Google Safe Browsing is not configured." },
    );
    expect(limits.some((l) => l.includes("not configured"))).toBe(true);
  });

  it("states that no-listing is not a safety guarantee", () => {
    const limits = deriveLimitations(FULL_COVERAGE, true, undefined);
    expect(limits.some((l) => /not a guarantee/i.test(l))).toBe(true);
  });

  it("discloses an unrecognised Safe Browsing payload", () => {
    const limits = deriveLimitations(
      { ...FULL_COVERAGE, safeBrowsing: "UNKNOWN" },
      true,
      undefined,
    );
    expect(limits.some((l) => /unrecognised/i.test(l))).toBe(true);
  });

  it("discloses missing page, redirect and reputation coverage", () => {
    const limits = deriveLimitations(
      {
        ...FULL_COVERAGE,
        page: false,
        redirects: false,
        reputation: false,
        safeBrowsing: "KNOWN_MALICIOUS",
      },
      false,
      undefined,
    );
    expect(limits.length).toBeGreaterThanOrEqual(4);
    expect(limits.some((l) => /Page contents/i.test(l))).toBe(true);
    expect(limits.some((l) => /redirect chain/i.test(l))).toBe(true);
    expect(limits.some((l) => /registration age/i.test(l))).toBe(true);
    expect(limits.some((l) => /AI analysis was unavailable/i.test(l))).toBe(true);
  });

  it("says nothing about Safe Browsing when it confirmed a threat", () => {
    const limits = deriveLimitations(
      { ...FULL_COVERAGE, safeBrowsing: "KNOWN_MALICIOUS" },
      true,
      undefined,
    );
    expect(limits.some((l) => /Safe Browsing/i.test(l))).toBe(false);
  });
});

describe("deriveAnalysisMode", () => {
  it("is ai-enhanced when the AI contributed findings", () => {
    expect(
      deriveAnalysisMode({ aiRan: true, aiSucceeded: true, aiFindings: 3, verdict: "SUSPICIOUS" }),
    ).toBe("ai-enhanced");
  });

  it("is degraded when the AI was needed but failed", () => {
    expect(
      deriveAnalysisMode({ aiRan: true, aiSucceeded: false, aiFindings: 0, verdict: "SUSPICIOUS" }),
    ).toBe("degraded");
  });

  it("is deterministic-only when the AI was correctly not needed", () => {
    expect(
      deriveAnalysisMode({ aiRan: false, aiSucceeded: false, aiFindings: 0, verdict: "SAFE" }),
    ).toBe("deterministic-only");
  });
});

describe("buildEvidence", () => {
  it("adds a dedicated Safe Browsing evidence item for a confirmed match", () => {
    const evidence = buildEvidence({
      factors: [],
      threat: { available: true, matched: true, source: "googlesafebrowsing", threatType: "social_engineering" },
      safeBrowsingStatus: "KNOWN_MALICIOUS",
    });

    const sb = evidence.find((e) => e.type === "SAFE_BROWSING_MATCH");
    expect(sb).toBeDefined();
    expect(sb?.confidence).toBe("confirmed");
    expect(sb?.source).toBe("safe_browsing");
  });

  it("does not add a Safe Browsing item for a clean lookup", () => {
    const evidence = buildEvidence({
      factors: [],
      safeBrowsingStatus: "NO_KNOWN_THREAT",
    });
    expect(evidence.some((e) => e.type === "SAFE_BROWSING_MATCH")).toBe(false);
  });

  it("does not add a Safe Browsing item when the lookup was unavailable", () => {
    const evidence = buildEvidence({
      factors: [],
      safeBrowsingStatus: "LOOKUP_UNAVAILABLE",
    });
    expect(evidence.some((e) => e.type === "SAFE_BROWSING_MATCH")).toBe(false);
  });
});
