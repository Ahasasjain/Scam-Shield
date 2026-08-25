import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  BackendThreatProvider,
  lookupThreatIntelligence,
  threatVerdictOverride,
} from "./threatIntelligenceAnalyzer";
import { deriveVerdict } from "./correlationEngine";

// Minimal chrome.storage mock for the cache layer.
const store = new Map<string, unknown>();
beforeEach(() => {
  store.clear();
  (globalThis as { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: vi.fn(async (key: string) =>
          store.has(key) ? { [key]: store.get(key) } : {},
        ),
        set: vi.fn(async (items: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(items)) store.set(k, v);
        }),
      },
    },
  };
});

describe("threat intelligence (spec §4–§7)", () => {
  it("returns available:false on network failure — never benign", async () => {
    const provider = new BackendThreatProvider({ baseUrl: "http://localhost:1" });
    const result = await provider.lookupUrl({
      normalizedUrl: "https://example.com",
      registrableDomain: "example.com",
    });
    expect(result.available).toBe(false);
    expect(result.matched).toBe(false);
  });

  it("reports matched when backend confirms a threat", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          available: true,
          matched: true,
          threatType: "phishing",
          confidence: "confirmed",
          source: "test-feed",
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const provider = new BackendThreatProvider({ baseUrl: "https://api.test" });
    const result = await provider.lookupUrl({
      normalizedUrl: "https://paypa1.com/login",
      registrableDomain: "paypa1.com",
    });
    expect(result.available).toBe(true);
    expect(result.matched).toBe(true);
    expect(result.confidence).toBe("confirmed");
    vi.unstubAllGlobals();
  });

  it("confirmed match produces a dangerous verdict override (§6)", () => {
    expect(
      threatVerdictOverride({
        available: true,
        matched: true,
        confidence: "confirmed",
        checkedAt: Date.now(),
      }),
    ).toBe("dangerous");
  });

  it("unavailable lookup never overrides to safe", () => {
    expect(
      threatVerdictOverride({ available: false, matched: false, checkedAt: Date.now() }),
    ).toBeNull();
  });

  it("caches negative results but never caches outages (§7)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ available: true, matched: false }), {
          status: 200,
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const provider = new BackendThreatProvider({ baseUrl: "https://api.test" });

    const first = await lookupThreatIntelligence(
      { normalizedUrl: "https://benign.example", registrableDomain: "benign.example" },
      provider,
    );
    expect(first.fromCache).toBe(false);

    const second = await lookupThreatIntelligence(
      { normalizedUrl: "https://benign.example", registrableDomain: "benign.example" },
      provider,
    );
    expect(second.fromCache).toBe(true); // negative cached short-TTL
    expect(fetchMock).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});

describe("deriveVerdict (spec §3, §30) — unknown is not safe", () => {
  const noIdentity = undefined;

  it("high score + official domain → known_safe", () => {
    expect(
      deriveVerdict({
        score: 100,
        domainIdentity: {
          hostname: "google.com",
          registrableDomain: "google.com",
          publicSuffix: "com",
          organizationDomain: "google.com",
          relationship: "official",
        },
        pageAnalyzed: true,
      }),
    ).toBe("known_safe");
  });

  it("high score + unrelated domain + NO page analysis → unknown (never safe)", () => {
    expect(
      deriveVerdict({ score: 100, domainIdentity: noIdentity, pageAnalyzed: false }),
    ).toBe("unknown");
  });

  it("high score + unrelated domain + page analyzed → low_risk", () => {
    expect(
      deriveVerdict({ score: 95, domainIdentity: noIdentity, pageAnalyzed: true }),
    ).toBe("low_risk");
  });

  it("lookalike → at least suspicious even with high score", () => {
    expect(
      deriveVerdict({
        score: 90,
        domainIdentity: {
          hostname: "g00gle.example",
          registrableDomain: "g00gle.example",
          publicSuffix: "example",
          organizationDomain: "g00gle.example",
          relationship: "lookalike",
          similarity: 0.9,
        },
        pageAnalyzed: false,
      }),
    ).toBe("suspicious");
  });

  it("mid scores map to suspicious/high_risk bands", () => {
    expect(deriveVerdict({ score: 60, pageAnalyzed: true })).toBe("suspicious");
    expect(deriveVerdict({ score: 40, pageAnalyzed: true })).toBe("high_risk");
    expect(deriveVerdict({ score: 10, pageAnalyzed: true })).toBe("dangerous");
  });
});

describe("generic phishing now scores risky (the core bug)", () => {
  // Simulates the previously-broken case: secure-login-verify.xyz with a
  // password form and urgency text used to score 80/"safe".
  it("credential page on unknown domain with pressure is suspicious or worse", () => {
    const factorIds = [
      "url-suspicious-tld",
      "url-hyphen-overload",
      "page-login-form",
      "page-urgency-language",
      "corr-unknown-credentials-pressure",
    ];
    const verdict = deriveVerdict({
      score: 70,
      pageAnalyzed: true,
      factorIds,
    });
    expect(verdict === "suspicious" || verdict === "high_risk").toBe(true);
  });

  it("cross-origin credential submission alone is high risk or dangerous", () => {
    const verdict = deriveVerdict({
      score: 70,
      pageAnalyzed: true,
      factorIds: ["page-cross-origin-credentials"],
    });
    expect(verdict === "high_risk" || verdict === "dangerous").toBe(true);
  });
});
