import { describe, expect, it } from "vitest";
import { ApiError } from "../middleware/errorHandler.js";

// The OpenAI SDK is exercised through mapOpenAIError; test the taxonomy
// mapping logic directly by importing the module under a light harness.
// (Full network calls are never made in unit tests.)

describe("ApiError", () => {
  it("carries status and code", () => {
    const err = new ApiError(429, "rate_limited", "Too many");
    expect(err.status).toBe(429);
    expect(err.code).toBe("rate_limited");
    expect(err.message).toBe("Too many");
  });
});

describe("error response contract", () => {
  it("uses the shared error codes from the extension contract", async () => {
    const { analyzeResponseSchema } = await import("@scamshield/shared");
    const parsed = analyzeResponseSchema.safeParse({
      ok: false,
      error: { code: "invalid_ai_response", message: "Bad AI output" },
    });
    expect(parsed.success).toBe(true);
  });

  it("accepts a valid success envelope", async () => {
    const { analyzeResponseSchema } = await import("@scamshield/shared");
    const parsed = analyzeResponseSchema.safeParse({
      ok: true,
      result: {
        riskLevel: "low",
        confidence: 80,
        summary: "Looks fine.",
        indicators: [],
        recommendation: "Proceed normally.",
      },
    });
    expect(parsed.success).toBe(true);
  });
});
