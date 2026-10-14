import { describe, expect, it } from "vitest";
import { decideAiNeed } from "./aiDecision";
import type { RiskFactor } from "@shared/index";

function factor(id: string): RiskFactor {
  return {
    id,
    title: id,
    description: "test evidence",
    severity: "medium",
    points: 5,
    source: "rule",
  };
}

describe("decideAiNeed", () => {
  it("does not request AI for weak or normal signals alone", () => {
    const result = decideAiNeed([
      factor("https-not-used"),
      factor("page-login-form"),
      factor("page-payment-form"),
      factor("url-excessive-length"),
      factor("url-suspicious-tld"),
      factor("url-nested-subdomains"),
      factor("url-brand-in-path"),
    ]);
    expect(result.needed).toBe(false);
  });

  it("requests AI for meaningful impersonation evidence", () => {
    const result = decideAiNeed([factor("url-brand-in-subdomain")]);
    expect(result.needed).toBe(true);
    expect(result.reasons).toContain("brand impersonation in a subdomain");
  });

  it("does not request AI for confirmed threat intelligence", () => {
    const result = decideAiNeed([factor("url-lookalike-domain-strong")], {
      available: true,
      matched: true,
    });
    expect(result.needed).toBe(false);
    expect(result.reasons).toEqual(["confirmed threat intelligence"]);
  });

  it("forces AI for temporary test mode when no confirmed threat exists", () => {
    const result = decideAiNeed([], undefined, true);
    expect(result.needed).toBe(true);
    expect(result.reasons).toEqual(["temporary AI test mode"]);
  });

  it("keeps confirmed threat intelligence authoritative in temporary test mode", () => {
    const result = decideAiNeed([], { available: true, matched: true }, true);
    expect(result.needed).toBe(false);
  });
});
