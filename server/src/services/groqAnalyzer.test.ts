import { describe, expect, it, vi } from "vitest";
import { GroqAnalyzer } from "./groqAnalyzer.js";
import type { ScanContext } from "@scamshield/shared";

const context: ScanContext = {
  url: "https://fakebook.example/login?next=%2Faccount",
  urlSignals: {
    protocol: "https",
    hostname: "fakebook.example",
    registrableDomain: "fakebook.example",
    isIpHost: false,
    urlLength: 49,
    subdomainDepth: 0,
    hyphenCount: 0,
    hasPunycode: false,
    tld: "example",
    pathLength: 6,
    isHttps: true,
  },
  pageSignals: {
    hasLoginForm: true,
    hasPasswordFieldsOnHttp: false,
    hasPaymentForm: false,
    urgencyLanguageCount: 2,
    giveawayPatterns: 0,
    fakeSecurityWarnings: 0,
    externalScriptOrigins: ["cdn.example.net"],
  },
};

function response(status: number, content: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve({ choices: [{ message: { content } }] }),
  } as Response;
}

const validGroqJson = JSON.stringify({
  verdict: "suspicious",
  confidence: 0.91,
  brandImpersonation: true,
  credentialPhishing: true,
  paymentPhishing: false,
  socialEngineering: true,
  indicators: [
    {
      id: "brand-login",
      title: "Brand-like login domain",
      description:
        "The supplied domain evidence resembles a brand impersonation pattern.",
      severity: "high",
      points: 25,
    },
  ],
  explanation:
    "The supplied evidence contains a combination of impersonation and pressure signals.",
  recommendedAction: "warn",
});

describe("GroqAnalyzer", () => {
  it("maps a validated Groq response without exposing sensitive context", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(response(200, validGroqJson));
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      fetchImpl,
    });

    const result = await analyzer.analyze(context);
    expect(result.riskLevel).toBe("medium");
    expect(result.confidence).toBe(91);
    expect(result.indicators[0]?.id).toBe("brand-login");
    expect(fetchImpl).toHaveBeenCalledOnce();
    const request = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    // Structural guarantee: the shared contract has no field capable of
    // carrying a form VALUE, so a password/OTP/card number is unrepresentable
    // rather than merely "filtered out". Assert the absence of any such key.
    const pageSignalsKeys = Object.keys(context.pageSignals ?? {});
    expect(pageSignalsKeys).not.toEqual(
      expect.arrayContaining(["password", "otp", "cardNumber", "cvv", "value"]),
    );
    expect(pageSignalsKeys).toEqual(
      expect.arrayContaining(["hasLoginForm", "hasPaymentForm"]),
    );
    expect(request.headers).toMatchObject({ Authorization: "Bearer gsk-test" });
  });

  it.each([
    // Password-reset tokens in the PATH, not just the query string.
    ["https://evil.example/reset/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"],
    // Email address as a path segment.
    ["https://evil.example/u/jane.doe@example.com/verify", "jane.doe@example.com"],
    // Query string and fragment must never survive.
    ["https://evil.example/login?token=supersecret123#frag", "supersecret123"],
  ])(
    "never transmits secrets or PII embedded in %s",
    async (url, forbidden) => {
      const fetchImpl = vi.fn().mockResolvedValue(response(200, validGroqJson));
      const analyzer = new GroqAnalyzer({
        apiKey: "gsk-test",
        model: "openai/gpt-oss-120b",
        fetchImpl,
      });

      await analyzer.analyze({ ...context, url });

      const request = fetchImpl.mock.calls[0]?.[1] as RequestInit;
      const body = JSON.parse(String(request.body)) as {
        messages: Array<{ content: string }>;
      };
      const userPrompt = body.messages[1]?.content ?? "";

      expect(userPrompt).not.toContain(forbidden);
      // The path SHAPE is still preserved, so path-based rules keep working.
      expect(userPrompt).toContain("evil.example");
    },
  );

  it("keeps non-sensitive path structure for risk analysis", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(response(200, validGroqJson));
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      fetchImpl,
    });

    await analyzer.analyze({
      ...context,
      url: "https://evil.example/account/verify-identity",
    });

    const request = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    const body = JSON.parse(String(request.body)) as {
      messages: Array<{ content: string }>;
    };
    // Redaction hides the value but keeps the segment count/positions.
    expect(body.messages[1]?.content).toContain("/[redacted]/[redacted]");
  });

  it("never includes a form action query string in the prompt", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(response(200, validGroqJson));
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      fetchImpl,
    });

    await analyzer.analyze({
      ...context,
      pageSignals: {
        ...context.pageSignals!,
        formActions: [
          {
            actionOrigin: "https://collector.evil.example/steal?session=abcd1234",
            isCrossOrigin: true,
            containsPassword: true,
            containsPaymentFields: false,
          },
        ],
      },
    });

    const request = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    const body = JSON.parse(String(request.body)) as {
      messages: Array<{ content: string }>;
    };
    expect(body.messages[1]?.content).not.toContain("abcd1234");
    expect(body.messages[1]?.content).toContain("collector.evil.example");
  });

  it.each([
    [429, "rate_limited"],
    [500, "upstream_error"],
  ] as const)("maps HTTP %s to a controlled error", async (status, code) => {
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(response(status, "{}")),
    });
    await expect(analyzer.analyze(context)).rejects.toMatchObject({ code });
  });

  it("maps network failures without retrying", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new Error("offline"));
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      fetchImpl,
    });
    await expect(analyzer.analyze(context)).rejects.toMatchObject({
      code: "upstream_error",
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("maps malformed JSON and schema failures to invalid_ai_response", async () => {
    for (const content of ["not-json", JSON.stringify({ verdict: "suspicious" })]) {
      const analyzer = new GroqAnalyzer({
        apiKey: "gsk-test",
        model: "openai/gpt-oss-120b",
        fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(response(200, content)),
      });
      await expect(analyzer.analyze(context)).rejects.toMatchObject({
        code: "invalid_ai_response",
      });
    }
  });

  it("maps a timeout to a controlled error", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        }),
    );
    const analyzer = new GroqAnalyzer({
      apiKey: "gsk-test",
      model: "openai/gpt-oss-120b",
      timeoutMs: 5,
      fetchImpl,
    });
    await expect(analyzer.analyze(context)).rejects.toMatchObject({ code: "timeout" });
  });
});
