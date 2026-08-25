import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import { analyzeResponseSchema } from "@scamshield/shared";

/** Typed application error with a stable machine-readable code. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code:
      | "invalid_request"
      | "rate_limited"
      | "unauthorized"
      | "upstream_error"
      | "timeout"
      | "invalid_ai_response"
      | "server_error",
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** 404 handler for unknown routes. */
export const notFoundHandler: RequestHandler = (_req, res) => {
  res
    .status(404)
    .json({ ok: false, error: { code: "not_found", message: "Route not found" } });
};

/**
 * Centralized error middleware — the ONLY place that maps errors to
 * responses. Always returns the shared AnalyzeResponse envelope shape.
 */
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (res.headersSent) return;

  if (err instanceof ZodError) {
    res.status(400).json(
      analyzeResponseSchema.parse({
        ok: false,
        error: {
          code: "invalid_request",
          message: "Request validation failed.",
        },
      }),
    );
    return;
  }

  if (err instanceof ApiError) {
    res.status(err.status).json({
      ok: false,
      error: { code: err.code, message: err.message },
    });
    return;
  }

  // Unknown error — never leak internals to clients.
  res.status(500).json({
    ok: false,
    error: { code: "server_error", message: "Internal server error." },
  });
};
