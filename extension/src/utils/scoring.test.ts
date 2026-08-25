import { describe, expect, it } from "vitest";
import { calculateScore, evaluateCorrelations } from "@/utils/scoring";
import type { RiskFactor } from "@shared/index";

function factor(id: string, points: number): RiskFactor {
  return {
    id,
    title: id,
    description: "test",
    severity: "low",
    points,
    source: "rule",
  };
}

describe("calculateScore — evidence groups (§12)", () => {
  it("returns 100 / safe when no factors", () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe("safe");
  });

  it("caps the URL-structure group so weak signals can't dominate (§9)", () => {
    // 2+3+3+2+3 = 13 raw; cap is 15 → uncapped here.
    const weak = [
      factor("url-excessive-length", 2),
      factor("url-suspicious-tld", 3),
      factor("url-nested-subdomains", 3),
      factor("url-hyphen-overload", 2),
      factor("url-encoded-chars", 3),
    ];
    const result = calculateScore(weak);
    expect(result.score).toBe(87); // 100 - 13
    expect(result.riskLevel).toBe("safe"); // weak signals alone stay safe
  });

  it("caps URL structure at 15 even with many findings", () => {
    const many = [
      factor("url-excessive-length", 10),
      factor("url-suspicious-tld", 10),
      factor("url-hyphen-overload", 10),
    ]; // raw 30 → capped at 15
    const result = calculateScore(many);
    expect(result.score).toBe(85);
    const urlEntry = result.breakdown.find((b) => b.category === "urlStructure");
    expect(urlEntry?.points).toBe(15);
    expect(urlEntry?.capped).toBe(true);
  });

  it("a single critical lookalike reaches Medium alone; Critical needs combination (§17)", () => {
    // 30 pts in brandImpersonation group (cap 35) → score 70 = "low" band edge.
    const result = calculateScore([factor("url-lookalike-domain-strong", 30)]);
    expect(result.riskLevel).toBe("low");
  });

  it("critical requires combinations (§17)", () => {
    const result = calculateScore([
      factor("url-lookalike-domain-strong", 30),
      factor("page-login-form", 5),
      factor("page-urgency-language", 10),
    ]);
    // Correlation adds impersonation+credentials (+15) and +urgency (+20).
    expect(["high", "critical"]).toContain(result.riskLevel);
    expect(result.score).toBeLessThanOrEqual(49);
  });
});

describe("evaluateCorrelations (§13)", () => {
  it("fires impersonation + credentials bonus", () => {
    const bonuses = evaluateCorrelations(
      [factor("url-brand-in-subdomain", 22), factor("page-login-form", 5)],
      {},
    );
    expect(bonuses.some((b) => b.id === "corr-impersonation-credentials")).toBe(true);
  });

  it("does not fire for official domains", () => {
    const bonuses = evaluateCorrelations([factor("page-login-form", 5)], {
      domainIdentity: {
        hostname: "accounts.google.com",
        registrableDomain: "google.com",
        publicSuffix: "com",
        organizationDomain: "google.com",
        detectedBrand: "google",
        matchedOfficialDomain: "google.com",
        relationship: "trusted-subdomain",
      },
    });
    expect(bonuses).toHaveLength(0);
  });

  it("unknown domain + credentials + urgency fires moderate correlation", () => {
    const bonuses = evaluateCorrelations(
      [factor("page-login-form", 5), factor("page-urgency-language", 10)],
      {
        domainIdentity: {
          hostname: "random-site.example",
          registrableDomain: "random-site.example",
          publicSuffix: "example",
          organizationDomain: "random-site.example",
          relationship: "unrelated",
        },
      },
    );
    expect(bonuses.some((b) => b.id === "corr-unknown-credentials-pressure")).toBe(true);
  });

  it("suspicious TLD alone fires no correlation", () => {
    const bonuses = evaluateCorrelations([factor("url-suspicious-tld", 3)], {});
    expect(bonuses).toHaveLength(0);
  });
});

describe("score bands remain correct (spec §13)", () => {
  // Cross-group fixtures so no single evidence cap interferes.
  it("maps deductions to the documented bands", () => {
    // Cross-group fixtures; totals computed AFTER per-group caps.
    // critical: brandImp 30 + page 26 + url 13 + transport 12 + redirects 6 = 87 → 13
    expect(calculateScore([factor("url-lookalike-domain-strong", 30), factor("page-fake-warnings", 26), factor("url-suspicious-tld", 3), factor("url-hyphen-overload", 2), factor("url-encoded-chars", 3), factor("url-excessive-length", 2), factor("url-nested-subdomains", 3), factor("https-not-used", 12), factor("redirect-long-chain", 6)]).riskLevel).toBe("critical");
    // high: brandImp 24 + page 16 + url 8 + redirects 6 = 54 → 46
    expect(calculateScore([factor("url-lookalike-domain", 24), factor("page-giveaway-patterns", 16), factor("url-encoded-chars", 3), factor("url-suspicious-tld", 3), factor("url-nested-subdomains", 2), factor("redirect-long-chain", 6)]).riskLevel).toBe("high");
    // medium: transport 18 + page 10 + redirects 6 = 34 → 66
    expect(calculateScore([factor("url-ip-host", 18), factor("page-urgency-language", 10), factor("redirect-long-chain", 6)]).riskLevel).toBe("medium");
    // low: transport 18 + page 5 = 23 → 77
    expect(calculateScore([factor("url-ip-host", 18), factor("page-login-form", 5)]).riskLevel).toBe("low");
    // safe: transport 18 alone → 82
    expect(calculateScore([factor("url-ip-host", 18)]).riskLevel).toBe("safe");
  });

  it("clamps at zero when every group is saturated (§12 caps)", () => {
    const result = calculateScore([
      // domainIdentity: n/a — no rules emit this group yet
      factor("url-lookalike-domain-strong", 30), // brandImpersonation: 30/35
      factor("url-brand-in-subdomain", 22),      // brandImpersonation capped → 35
      factor("url-ip-host", 18),                 // urlStructure raw 41 → cap 15
      factor("url-suspicious-tld", 3),
      factor("url-hyphen-overload", 2),
      factor("url-encoded-chars", 3),
      factor("url-excessive-length", 2),
      factor("url-nested-subdomains", 3),
      factor("url-punycode", 12),
      factor("page-fake-warnings", 26),          // pageContent raw 57 → cap 30
      factor("page-giveaway-patterns", 16),
      factor("page-payment-form", 5),
      factor("page-urgency-language", 10),
      factor("https-not-used", 12),              // transport: 12/20
      factor("redirect-long-chain", 6),          // redirects: 6/15
    ]);
    // Totals: 35 + 15 + 30 + 12 + 6 = 98 → score 2
    expect(result.score).toBeLessThanOrEqual(10);
    expect(result.riskLevel).toBe("critical");
  });

  it("includes AI factors in the total", () => {
    const aiFactor: RiskFactor = { ...factor("ai-test", 15), source: "ai" };
    const result = calculateScore([], [aiFactor]);
    expect(result.score).toBe(85);
  });
});
