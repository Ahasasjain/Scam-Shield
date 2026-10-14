import rateLimit from "express-rate-limit";
import type { RequestHandler } from "express";

/**
 * Rate limiter (spec §27/§33).
 *
 * Scoped per route. A single global limiter was a functional bug: the
 * extension calls `/api/threat-lookup` on every page scan, so a browsing
 * session burned through a shared budget and then started failing the
 * expensive `/api/analyze` calls too. Threat lookups are cheap and heavily
 * cached; only the AI endpoint needs a tight budget.
 */

function envelope(message: string) {
  return {
    ok: false,
    error: { code: "rate_limited" as const, message },
  };
}

/**
 * A 429 from /api/threat-lookup must speak the threat-lookup contract, not
 * the analyze envelope: the extension's threat provider reads `available`,
 * and an unparseable shape would only degrade to a generic "unavailable"
 * (safe, but it discards the real reason — rate limiting).
 */
function threatEnvelope(message: string) {
  return {
    available: false,
    matched: false,
    status: "UNAVAILABLE" as const,
    safeBrowsingStatus: "UNKNOWN" as const,
    reason: message,
  };
}

/** Expensive AI analysis — the tightest budget, since each call costs money. */
export function createAiRateLimiter(max: number, windowMinutes: number): RequestHandler {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json(envelope("Too many analyses. Try again later."));
    },
  });
}

/**
 * Threat-intelligence lookups — called on every navigation, so it gets a much
 * larger budget. The in-memory cache absorbs most repeats.
 */
export function createThreatRateLimiter(
  max: number,
  windowMinutes: number,
): RequestHandler {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json(threatEnvelope("Too many lookups. Try again shortly."));
    },
  });
}
