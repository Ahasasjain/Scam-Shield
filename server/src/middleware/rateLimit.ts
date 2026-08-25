import rateLimit from "express-rate-limit";
import type { RequestHandler } from "express";

/** Rate limiter for the AI endpoint (spec §27/§33). */
export function createRateLimiter(max: number, windowMinutes: number): RequestHandler {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      ok: false,
      error: { code: "rate_limited", message: "Too many requests. Try again later." },
    },
  });
}
