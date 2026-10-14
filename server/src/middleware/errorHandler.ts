import type { ErrorRequestHandler, RequestHandler } from "express";
import { ZodError } from "zod";
import { analyzeResponseSchema } from "@scamshield/shared";
import { logger } from "../lib/logger.js";

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
    .json(
      analyzeResponseSchema.parse({
        ok: false,
        error: { code: "not_found", message: "Route not found" },
      }),
    );
};

/**
 * Centralized error middleware — the ONLY place that maps errors to
 * responses. Always returns the shared AnalyzeResponse envelope shape.
 *
 * Every branch is validated through `analyzeResponseSchema` so that a new
 * error code can never ship an envelope the extension cannot parse
 * (spec §21 rule 12: validate and sanitize external responses).
 */
export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (res.headersSent) return;

  // express.json() rejects oversized payloads with a 413 before any route
  // runs. That is a client error (invalid_request), not a server failure —
  // a 500 here would page an operator for a malformed client upload.
  if (
    typeof err === "object" &&
    err !== null &&
    (err as { status?: unknown }).status === 413
  ) {
    res.status(400).json(
      analyzeResponseSchema.parse({
        ok: false,
        error: {
          code: "invalid_request",
          message: "Request payload too large.",
        },
      }),
    );
    return;
  }

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
    res.status(err.status).json(
      analyzeResponseSchema.parse({
        ok: false,
        error: { code: err.code, message: err.message },
      }),
    );
    return;
  }

  // body-parser rejects malformed JSON with a status-400 SyntaxError before
  // any route runs. That is a client error, not a server failure.
  if (
    typeof err === "object" &&
    err !== null &&
    (err as { status?: unknown }).status === 400
  ) {
    res.status(400).json(
      analyzeResponseSchema.parse({
        ok: false,
        error: {
          code: "invalid_request",
          message: "Malformed JSON payload.",
        },
      }),
    );
    return;
  }

  // Unknown error — never leak internals to clients, but always log them
  // for operators: a silent 500 is undebuggable in production.
  logger.error({ err }, "Unhandled route error");
  res.status(500).json(
    analyzeResponseSchema.parse({
      ok: false,
      error: { code: "server_error", message: "Internal server error." },
    }),
  );
};
