import { describe, expect, it } from "vitest";
import { runRuleEngine } from "@/services/scanner";
import type { ScanContext } from "@/services/scanner/ruleEngine";

function makeContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    url: "https://www.example.com/",
    urlSignals: {
      protocol: "https",
      hostname: "www.example.com",
      registrableDomain: "example.com",
      isHttps: true,
      isIpHost: false,
      urlLength: 27,
      subdomainDepth: 1,
      hyphenCount: 0,
      hasPunycode: false,
      tld: "com",
      pathLength: 1,
    },
    pageSignals: {
      hasLoginForm: false,
      hasPasswordFieldsOnHttp: false,
      hasPaymentForm: false,
      urgencyLanguageCount: 0,
      giveawayPatterns: 0,
      fakeSecurityWarnings: 0,
      externalScriptOrigins: [],
    },
    redirectSignals: { chainLength: 0, crossOriginHops: 0, finalUrl: "" },
    ...overrides,
  };
}

describe("runRuleEngine", () => {
  it("returns no factors for a benign context", () => {
    const { factors } = runRuleEngine(makeContext());
    expect(factors).toHaveLength(0);
  });

  it("flags IP host with high severity", () => {
    const { factors } = runRuleEngine(
      makeContext({
        url: "http://192.168.1.1/login",
        urlSignals: {
          ...makeContext().urlSignals,
          hostname: "192.168.1.1",
          isIpHost: true,
          isHttps: false,
          protocol: "http",
        },
      }),
    );
    const ipRule = factors.find((f) => f.id === "url-ip-host");
    expect(ipRule).toBeDefined();
    expect(ipRule?.severity).toBe("high");
  });

  it("flags punycode domains", () => {
    const { factors } = runRuleEngine(
      makeContext({
        urlSignals: {
          ...makeContext().urlSignals,
          hostname: "xn--pple-43d.com",
          hasPunycode: true,
        },
      }),
    );
    expect(factors.some((f) => f.id === "url-punycode")).toBe(true);
  });

  it("flags fake security warnings as critical", () => {
    const { factors } = runRuleEngine(
      makeContext({
        pageSignals: {
          hasLoginForm: false,
          hasPasswordFieldsOnHttp: false,
          hasPaymentForm: false,
          urgencyLanguageCount: 0,
          giveawayPatterns: 0,
          fakeSecurityWarnings: 2,
          externalScriptOrigins: [],
        },
      }),
    );
    const rule = factors.find((f) => f.id === "page-fake-warnings");
    expect(rule?.severity).toBe("critical");
  });

  it("flags password fields over HTTP as critical", () => {
    const { factors } = runRuleEngine(
      makeContext({
        urlSignals: { ...makeContext().urlSignals, isHttps: false, protocol: "http" },
        pageSignals: {
          ...makeContext().pageSignals!,
          hasLoginForm: true,
          hasPasswordFieldsOnHttp: true,
        },
      }),
    );
    expect(factors.some((f) => f.id === "page-password-over-http")).toBe(true);
  });

  it("skips page rules when page signals are absent", () => {
    const context = makeContext();
    delete (context as { pageSignals?: unknown }).pageSignals;
    const { factors, skippedRuleIds } = runRuleEngine(context);
    expect(factors.every((f) => !f.id.startsWith("page-"))).toBe(true);
    expect(skippedRuleIds.length).toBeGreaterThan(0);
  });

  it("every factor includes an explanation", () => {
    const { factors } = runRuleEngine(
      makeContext({
        urlSignals: { ...makeContext().urlSignals, isHttps: false, protocol: "http" },
      }),
    );
    for (const factor of factors) {
      expect(factor.description.length).toBeGreaterThan(0);
      expect(factor.points).toBeGreaterThanOrEqual(0);
      expect(factor.source).toBe("rule");
    }
  });
});
