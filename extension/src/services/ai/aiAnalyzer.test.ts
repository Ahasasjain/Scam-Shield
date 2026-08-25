import { describe, expect, it, vi, afterEach } from "vitest";
import { HttpAIAnalyzer } from "@/services/ai/aiAnalyzer";
import type { ScanContext } from "@/services/scanner/ruleEngine";

const validAiResult = {
  riskLevel: "medium",
  confidence: 72,
  summary: "Some indicators suggest caution.",
  indicators: [
    {
      id: "sig-1",
      title: "Unusual URL structure",
      description: "The URL pattern is atypical.",
      severity: "medium",
      points: 10,
    },
  ],
  recommendation: "Verify the site before entering information.",
};

const context: ScanContext = {
  url: "https://example.com",
  urlSignals: {
    protocol: "https",
    hostname: "example.com",
    registrableDomain: "example.com",
    isHttps: true,
    isIpHost: false,
    urlLength: 20,
    subdomainDepth: 0,
    hyphenCount: 0,
    hasPunycode: false,
    tld: "com",
    pathLength: 1,
  },
};

// Mock the axios client factory so no real network calls occur.
vi.mock("@/services/api/httpClient", () => ({
  ApiClientError: class ApiClientError extends Error {
    constructor(
      public code: string,
      message: string,
    ) {
      super(message);
    }
  },
  createApiClient: vi.fn(() => ({
    post: vi.fn(),
  })),
  parseEnvelope: vi.fn(
    (
      schema: { safeParse: (d: unknown) => { success: boolean; data?: unknown } },
      data: unknown,
    ) => {
      const parsed = schema.safeParse(data);
      if (!parsed.success) throw new Error("invalid");
      return parsed.data;
    },
  ),
}));

async function getMocks() {
  const httpClient = await import("@/services/api/httpClient");
  const factory = vi.mocked(httpClient.createApiClient);
  return { httpClient, factory };
}

describe("HttpAIAnalyzer", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("returns a validated result on success", async () => {
    const { factory } = await getMocks();
    const post = vi.fn().mockResolvedValue({
      data: { ok: true, result: validAiResult },
    });
    factory.mockReturnValue({ post } as never);

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test" });
    const outcome = await analyzer.analyze(context);

    expect(outcome.status).toBe("ok");
    if (outcome.status === "ok") {
      expect(outcome.result.confidence).toBe(72);
      expect(outcome.result.indicators).toHaveLength(1);
    }
    expect(post).toHaveBeenCalledWith("/api/analyze", { context });
  });

  it("rejects hostile/malformed AI payloads", async () => {
    const { httpClient, factory } = await getMocks();
    const post = vi.fn().mockResolvedValue({
      data: { ok: true, result: { riskLevel: "totally-invalid", confidence: "high" } },
    });
    factory.mockReturnValue({ post } as never);

    // Real schema validation still runs inside analyze().
    vi.mocked(httpClient.parseEnvelope).mockImplementationOnce((schema, data) =>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (schema as any).safeParse(data).success
        ? (data as never)
        : (() => {
            throw new httpClient.ApiClientError("invalid_response", "bad");
          })(),
    );

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test" });
    const outcome = await analyzer.analyze(context);
    expect(outcome.status).toBe("unavailable");
  });

  it("reports unavailable on rate limit without retrying", async () => {
    const { httpClient, factory } = await getMocks();
    const post = vi
      .fn()
      .mockRejectedValue(
        new httpClient.ApiClientError("rate_limited", "Rate limited."),
      );
    factory.mockReturnValue({ post } as never);

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test" });
    const outcome = await analyzer.analyze(context);

    expect(outcome.status).toBe("unavailable");
    if (outcome.status === "unavailable") {
      expect(outcome.reason).toContain("rate limit");
    }
    expect(post).toHaveBeenCalledTimes(1); // no retry on 429
  });

  it("retries on server errors then succeeds", async () => {
    const { httpClient, factory } = await getMocks();
    const post = vi
      .fn()
      .mockRejectedValueOnce(new httpClient.ApiClientError("server_error", "boom"))
      .mockResolvedValue({ data: { ok: true, result: validAiResult } });
    factory.mockReturnValue({ post } as never);

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test" });
    const outcome = await analyzer.analyze(context);

    expect(post).toHaveBeenCalledTimes(2);
    expect(outcome.status).toBe("ok");
  });

  it("reports timeout when the request times out", async () => {
    const { httpClient, factory } = await getMocks();
    const post = vi
      .fn()
      .mockRejectedValue(new httpClient.ApiClientError("timeout", "timed out"));
    factory.mockReturnValue({ post } as never);

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test", timeoutMs: 10 });
    const outcome = await analyzer.analyze(context);

    expect(outcome).toMatchObject({
      status: "unavailable",
      reason: "AI analysis timed out.",
    });
  });

  it("rejects an API error envelope without retrying invalid responses", async () => {
    const { factory } = await getMocks();
    const post = vi.fn().mockResolvedValue({
      data: { ok: false, error: { code: "upstream_error", message: "provider down" } },
    });
    factory.mockReturnValue({ post } as never);

    const analyzer = new HttpAIAnalyzer({ baseUrl: "https://api.test" });
    const outcome = await analyzer.analyze(context);

    expect(outcome.status).toBe("unavailable");
    expect(post).toHaveBeenCalledTimes(1);
  });
});
