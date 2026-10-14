import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupGoogleSafeBrowsing } from "./safeBrowsing.js";

/**
 * Spec §2 / §22 coverage:
 * - Safe Browsing malicious result
 * - Safe Browsing no-match
 * - Safe Browsing API failure (HTTP error, rate limit, malformed body)
 * - unknown Safe Browsing state
 * - not-configured coverage gap
 *
 * The central invariant under test (spec §21 rule 2): a no-match is NOT proof
 * of safety, and an outage is NOT a no-match.
 */

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function stubFetchOk(body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify(body), { status: 200 }),
    ),
  );
}

describe("Google Safe Browsing lookup", () => {
  it("reports LOOKUP_UNAVAILABLE when no API key is configured", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "");
    vi.stubEnv("GCSB_API_KEY", "");

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    // NOT null and NOT a clean result: an unconfigured provider is a gap in
    // coverage, and the extension must render it as UNKNOWN.
    expect(result).toMatchObject({
      available: false,
      matched: false,
      status: "LOOKUP_UNAVAILABLE",
    });
    expect(result.reason).toMatch(/not configured/i);
  });

  it("accepts the GCSB_API_KEY alias", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "");
    vi.stubEnv("GCSB_API_KEY", "alias-key");
    stubFetchOk({});

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result.status).toBe("NO_KNOWN_THREAT");
  });

  it("returns NO_KNOWN_THREAT for a well-formed empty response", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    stubFetchOk({});

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: true,
      matched: false,
      status: "NO_KNOWN_THREAT",
      source: "googlesafebrowsing",
    });
  });

  it("returns NO_KNOWN_THREAT for an empty matches array", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    stubFetchOk({ matches: [] });

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: true,
      matched: false,
      status: "NO_KNOWN_THREAT",
    });
  });

  it("returns confirmed evidence for a KNOWN_MALICIOUS match", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    stubFetchOk({ matches: [{ threatType: "SOCIAL_ENGINEERING" }] });

    const result = await lookupGoogleSafeBrowsing("https://phishing.example/");

    expect(result).toMatchObject({
      available: true,
      matched: true,
      status: "KNOWN_MALICIOUS",
      confidence: "confirmed",
      threatType: "social_engineering",
    });
  });

  it("does not fabricate a threat type when the provider omits it", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    stubFetchOk({ matches: [{}] });

    const result = await lookupGoogleSafeBrowsing("https://phishing.example/");

    expect(result.matched).toBe(true);
    expect(result.threatType).toBeUndefined();
  });

  it("returns LOOKUP_UNAVAILABLE on a network failure", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: false,
      matched: false,
      status: "LOOKUP_UNAVAILABLE",
    });
  });

  it("distinguishes a rate limit from a generic failure", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 429 })),
    );

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result.status).toBe("LOOKUP_UNAVAILABLE");
    expect(result.reason).toMatch(/rate limit/i);
  });

  it("flags a rejected key distinctly from other HTTP errors", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 401 })),
    );

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result.reason).toMatch(/rejected the configured key/i);
  });

  it("returns LOOKUP_UNAVAILABLE on a 5xx provider error", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 500 })),
    );

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: false,
      status: "LOOKUP_UNAVAILABLE",
    });
    expect(result.reason).toMatch(/status 500/);
  });

  it("treats a malformed JSON body as unavailable, not as a clean result", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("not-json", { status: 200 }),
      ),
    );

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: false,
      status: "LOOKUP_UNAVAILABLE",
    });
  });

  it("returns UNKNOWN for a well-formed but unrecognised payload shape", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    // `matches` present but not an array of objects we understand.
    stubFetchOk({ matches: "unexpected", extra: 1 });

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result).toMatchObject({
      available: false,
      matched: false,
      status: "UNKNOWN",
    });
  });

  it("returns LOOKUP_UNAVAILABLE when the lookup times out", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    // Abort with the same error shape the AbortController produces.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() => {
        const error = new Error("The operation was aborted.");
        error.name = "AbortError";
        return Promise.reject(error);
      }),
    );

    const result = await lookupGoogleSafeBrowsing("https://example.com/");

    expect(result.status).toBe("LOOKUP_UNAVAILABLE");
    expect(result.reason).toMatch(/timed out/i);
  });

  it("sends the API key in the query string and a well-formed request body", async () => {
    vi.stubEnv("GOOGLE_SAFEBROWSING_API_KEY", "test-key");
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await lookupGoogleSafeBrowsing("https://example.com/path?q=1");

    const [requestUrl, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(requestUrl).toContain("key=test-key");
    const body = JSON.parse(String(init.body)) as {
      client: { clientId: string };
      threatInfo: { threatEntries: Array<{ url: string }> };
    };
    expect(body.client.clientId).toBe("scamshield");
    expect(body.threatInfo.threatEntries[0]?.url).toBe("https://example.com/path?q=1");
  });
});
