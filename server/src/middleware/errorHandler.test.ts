import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { analyzeResponseSchema } from "@scamshield/shared";
import { ApiError, errorHandler, notFoundHandler } from "./errorHandler.js";

/**
 * Replaces the former `openaiAnalyzer.test.ts`, which asserted almost nothing
 * and referenced a deleted provider. These tests drive the real Express
 * handlers and assert the emitted envelope actually satisfies the shared
 * contract the extension parses (spec §21 rule 12).
 */

function fakeRes() {
  const res = {
    statusCode: 0,
    body: undefined as unknown,
    headersSent: false,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

const req = {} as never;
const next = vi.fn();

describe("ApiError", () => {
  it("carries status and code", () => {
    const err = new ApiError(429, "rate_limited", "Too many");
    expect(err.status).toBe(429);
    expect(err.code).toBe("rate_limited");
    expect(err.message).toBe("Too many");
  });
});

describe("notFoundHandler", () => {
  it("emits a contract-valid not_found envelope", () => {
    const res = fakeRes();
    notFoundHandler(req, res as never, next);

    expect(res.statusCode).toBe(404);
    expect(analyzeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toMatchObject({
      ok: false,
      error: { code: "not_found" },
    });
  });
});

describe("errorHandler", () => {
  it("maps a ZodError to 400 invalid_request", () => {
    const res = fakeRes();
    // Produce a genuine ZodError rather than hand-building issue objects,
    // so the test does not depend on the Zod issue schema shape.
    const parsed = z.object({ url: z.string().url() }).safeParse({ url: 42 });
    expect(parsed.success).toBe(false);
    if (parsed.success) throw new Error("expected the fixture to fail validation");

    errorHandler(parsed.error, req, res as never, next);

    expect(res.statusCode).toBe(400);
    expect(analyzeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toMatchObject({ error: { code: "invalid_request" } });
  });

  it("maps an ApiError to its own status and code", () => {
    const res = fakeRes();
    errorHandler(
      new ApiError(504, "timeout", "Upstream timed out"),
      req,
      res as never,
      next,
    );

    expect(res.statusCode).toBe(504);
    expect(analyzeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toMatchObject({ error: { code: "timeout" } });
  });

  it("maps a body-parser SyntaxError to 400 invalid_request, not 500", () => {
    const res = fakeRes();
    // express.json() throws this shape for malformed JSON before any route
    // runs. Surfacing it as server_error would blame the server (and page an
    // operator) for a client mistake.
    const parseError = new SyntaxError("Unexpected token in JSON");
    (parseError as unknown as Record<string, unknown>)["status"] = 400;

    errorHandler(parseError, req, res as never, next);

    expect(res.statusCode).toBe(400);
    expect(analyzeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body).toMatchObject({ error: { code: "invalid_request" } });
  });

  it("does not leak internals for an unknown error", () => {
    const res = fakeRes();
    errorHandler(
      new Error("connection string postgres://user:hunter2@db/x failed"),
      req,
      res as never,
      next,
    );

    expect(res.statusCode).toBe(500);
    expect(analyzeResponseSchema.safeParse(res.body).success).toBe(true);
    expect(JSON.stringify(res.body)).not.toMatch(/hunter2|postgres/i);
  });

  it("no-ops once headers have been sent", () => {
    const res = fakeRes();
    res.headersSent = true;
    errorHandler(new Error("late"), req, res as never, next);

    expect(res.statusCode).toBe(0);
    expect(res.body).toBeUndefined();
  });
});

describe("error response contract", () => {
  it("accepts a valid success envelope", () => {
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

  it("rejects an unknown error code so drift is caught at build time", () => {
    const parsed = analyzeResponseSchema.safeParse({
      ok: false,
      error: { code: "totally_made_up", message: "nope" },
    });
    expect(parsed.success).toBe(false);
  });
});
