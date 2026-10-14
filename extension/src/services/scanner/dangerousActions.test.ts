import { describe, expect, it } from "vitest";
import type { ScanContext } from "./ruleEngine";
import { runRuleEngine } from "./index";
import { evaluateCorrelations, deriveVerdict } from "./correlationEngine";
import { decideAiNeed } from "./aiDecision";

/**
 * Spec §3 / §6 / §14 / §22 coverage for dangerous-action detection.
 *
 * The two properties that matter most:
 *  1. A legitimate login page must NOT trip these rules (minimise false
 *     positives, spec §3 / §21 rule 8).
 *  2. A page asking for an OTP or submitting credentials off-domain MUST.
 */

function contextWith(pageSignals: NonNullable<ScanContext["pageSignals"]>): ScanContext {
  return {
    url: "https://example.test/login",
    urlSignals: {
      protocol: "https:",
      hostname: "example.test",
      registrableDomain: "example.test",
      isHttps: true,
      isIpHost: false,
      urlLength: 27,
      subdomainDepth: 0,
      hyphenCount: 0,
      hasPunycode: false,
      tld: "test",
      pathLength: 6,
    },
    pageSignals,
  };
}

const EMPTY_PAGE = {
  hasLoginForm: false,
  hasPasswordFieldsOnHttp: false,
  hasPaymentForm: false,
  urgencyLanguageCount: 0,
  giveawayPatterns: 0,
  fakeSecurityWarnings: 0,
  externalScriptOrigins: [] as string[],
  formActions: [] as never[],
  sensitiveKinds: [] as string[],
  crossOriginSensitiveForms: 0,
  offDomainSensitiveForms: 0,
  suspiciousDownloadCount: 0,
};

function idsFor(pageSignals: NonNullable<ScanContext["pageSignals"]>): string[] {
  return runRuleEngine(contextWith(pageSignals)).factors.map((f) => f.id);
}

describe("dangerous action rules (spec §3)", () => {
  it("does not flag a plain legitimate login page", () => {
    const ids = idsFor({
      ...EMPTY_PAGE,
      hasLoginForm: true,
      sensitiveKinds: ["password"],
      formActions: [
        {
          actionOrigin: "https://example.test",
          isCrossOrigin: false,
          containsPassword: true,
          containsPaymentFields: false,
          kinds: ["password"],
        },
      ],
    });

    // A same-origin password form is normal on thousands of real sites.
    expect(ids).not.toContain("page-otp-collection");
    expect(ids).not.toContain("page-cvv-collection");
    expect(ids).not.toContain("page-offdomain-sensitive-submit");
    expect(ids).not.toContain("page-suspicious-download");
  });

  it("flags an OTP request", () => {
    const ids = idsFor({ ...EMPTY_PAGE, sensitiveKinds: ["otp", "password"] });
    expect(ids).toContain("page-otp-collection");
  });

  it("flags a CVV request", () => {
    const ids = idsFor({
      ...EMPTY_PAGE,
      hasPaymentForm: true,
      sensitiveKinds: ["card", "cvv"],
    });
    expect(ids).toContain("page-cvv-collection");
    expect(ids).toContain("page-payment-form");
  });

  it("flags UPI collection (§14 India-specific)", () => {
    const ids = idsFor({ ...EMPTY_PAGE, sensitiveKinds: ["upi"] });
    expect(ids).toContain("page-upi-collection");
  });

  it("flags banking credentials", () => {
    const ids = idsFor({ ...EMPTY_PAGE, sensitiveKinds: ["banking", "password"] });
    expect(ids).toContain("page-banking-credentials");
  });

  it("flags sensitive personal data", () => {
    const ids = idsFor({ ...EMPTY_PAGE, sensitiveKinds: ["personal"] });
    expect(ids).toContain("page-sensitive-personal-data");
  });

  it("flags an off-domain sensitive submission", () => {
    const ids = idsFor({
      ...EMPTY_PAGE,
      sensitiveKinds: ["password"],
      formActions: [
        {
          actionOrigin: "https://collector.evil.test",
          isCrossOrigin: true,
          containsPassword: true,
          containsPaymentFields: false,
          kinds: ["password"],
        },
      ],
      crossOriginSensitiveForms: 1,
      offDomainSensitiveForms: 1,
    });
    expect(ids).toContain("page-offdomain-sensitive-submit");
  });

  it("flags a suspicious download", () => {
    const ids = idsFor({ ...EMPTY_PAGE, suspiciousDownloadCount: 2 });
    expect(ids).toContain("page-suspicious-download");
  });

  it("does not flag fake verification when no such language is present", () => {
    const ids = idsFor({ ...EMPTY_PAGE, giveawayPatterns: 0 });
    expect(ids).not.toContain("page-fake-verification");
  });
});

describe("correlation with new signals (spec §11)", () => {
  it("combines impersonation with an OTP request", () => {
    const factors = [
      { id: "url-lookalike-domain-strong", title: "t", description: "d", severity: "critical" as const, points: 30, source: "rule" as const },
      { id: "page-otp-collection", title: "t", description: "d", severity: "high" as const, points: 26, source: "rule" as const },
    ];

    const bonuses = evaluateCorrelations(factors, {
      domainIdentity: {
        hostname: "paypa1-secure.test",
        registrableDomain: "paypa1-secure.test",
        publicSuffix: "test",
        organizationDomain: "paypa1-secure.test",
        relationship: "lookalike",
      },
    });

    expect(bonuses.map((b) => b.id)).toContain("corr-impersonation-otp");
  });

  it("combines UPI collection with a payment form on an unknown domain (§14)", () => {
    const factors = [
      { id: "page-upi-collection", title: "t", description: "d", severity: "medium" as const, points: 16, source: "rule" as const },
      { id: "page-payment-form", title: "t", description: "d", severity: "medium" as const, points: 14, source: "rule" as const },
    ];

    const bonuses = evaluateCorrelations(factors, {
      domainIdentity: {
        hostname: "refund-claim.test",
        registrableDomain: "refund-claim.test",
        publicSuffix: "test",
        organizationDomain: "refund-claim.test",
        relationship: "unrelated",
      },
    });

    expect(bonuses.map((b) => b.id)).toContain("corr-upi-refund-scam");
  });

  it("does not fire the UPI scam bonus on an official brand domain", () => {
    const factors = [
      { id: "page-upi-collection", title: "t", description: "d", severity: "medium" as const, points: 16, source: "rule" as const },
      { id: "page-payment-form", title: "t", description: "d", severity: "medium" as const, points: 14, source: "rule" as const },
    ];

    const bonuses = evaluateCorrelations(factors, {
      domainIdentity: {
        hostname: "paypal.com",
        registrableDomain: "paypal.com",
        publicSuffix: "com",
        organizationDomain: "paypal.com",
        relationship: "official",
      },
    });

    expect(bonuses.map((b) => b.id)).not.toContain("corr-upi-refund-scam");
  });
});

describe("verdict derivation with dangerous actions", () => {
  it("escalates an off-domain credential submission to at least HIGH_RISK", () => {
    const verdict = deriveVerdict({
      score: 60,
      factorIds: ["page-offdomain-sensitive-submit"],
      pageAnalyzed: true,
    });
    expect(["HIGH_RISK", "DANGEROUS"]).toContain(verdict);
  });

  it("does not escalate an OTP request on an official brand domain", () => {
    const verdict = deriveVerdict({
      score: 80,
      factorIds: ["page-otp-collection"],
      pageAnalyzed: true,
      domainIdentity: {
        hostname: "bank.example",
        registrableDomain: "bank.example",
        publicSuffix: "example",
        organizationDomain: "bank.example",
        relationship: "official",
      },
    });
    expect(verdict).toBe("LOW_RISK");
  });
});

describe("AI gating (spec §9 — do not call AI for every URL)", () => {
  it("does not call the AI for a plain legitimate login page", () => {
    const factors = runRuleEngine(
      contextWith({
        ...EMPTY_PAGE,
        hasLoginForm: true,
        sensitiveKinds: ["password"],
      }),
    ).factors;

    expect(decideAiNeed(factors).needed).toBe(false);
  });

  it("calls the AI for an OTP request, which is genuinely ambiguous", () => {
    const factors = runRuleEngine(
      contextWith({ ...EMPTY_PAGE, sensitiveKinds: ["otp", "password"] }),
    ).factors;

    expect(decideAiNeed(factors).needed).toBe(true);
  });
});
