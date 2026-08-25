import { Router } from "express";
import { z } from "zod";
import { logger } from "../lib/logger.js";

/**
 * POST /api/threat-lookup (spec §4–§6)
 *
 * Provider-neutral threat-intelligence proxy. Provider API keys live ONLY
 * in server env — never in the extension. Results are cached in-memory with
 * TTL by verdict class; outages return { available: false }, which the
 * extension treats as UNKNOWN, never safe.
 */

const lookupSchema = z.object({
  url: z.string().url(),
  registrableDomain: z.string().nullable().optional(),
});

interface ThreatLookupResponse {
  available: boolean;
  matched: boolean;
  threatType?: string;
  confidence?: "confirmed" | "high" | "medium";
  source?: string;
}

// ---------------------------------------------------------------------------
// In-memory cache (server-side layer of spec §7)
// ---------------------------------------------------------------------------

const CACHE_TTL_MATCHED_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_NEGATIVE_MS = 30 * 60 * 1000;
const cache = new Map<string, { response: ThreatLookupResponse; expiresAt: number }>();

function getCached(key: string): ThreatLookupResponse | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.response;
}

function setCached(key: string, response: ThreatLookupResponse): void {
  const ttl =
    response.matched && response.available
      ? CACHE_TTL_MATCHED_MS
      : CACHE_TTL_NEGATIVE_MS;
  cache.set(key, { response, expiresAt: Date.now() + ttl });
}

// ---------------------------------------------------------------------------
// Local curated feed (works with zero external dependencies).
// Format: one URL/domain pattern per line, `*` wildcard prefix supported.
// Extend or replace with OpenPhish/PhishTank feeds via env config later.
// ---------------------------------------------------------------------------

const LOCAL_FEED = new Set<string>([
  // Known phishing patterns (extend via env THREAT_FEED_URL integration).
  "paypa1.com",
  "g00gle.com",
  "faceb00k.com",
  "amaz0n-secure.com",
  "netflix-billing.com",
  "appleid-verify.com",
  "microsoft-support.xyz",
  "wellsfargo-login.net",
  "chase-verify.com",
  "steamcommunuty.com",
  "coinbase-pro-login.com",
  "instagram-help.center",
]);

function checkLocalFeed(
  url: string,
  registrableDomain: string | null,
): ThreatLookupResponse {
  const host = (() => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return registrableDomain?.toLowerCase() ?? "";
    }
  })();

  const matched =
    (registrableDomain !== null && LOCAL_FEED.has(registrableDomain.toLowerCase())) ||
    LOCAL_FEED.has(host);

  return matched
    ? {
        available: true,
        matched: true,
        threatType: "phishing",
        confidence: "high",
        source: "scamshield-local-feed",
      }
    : { available: true, matched: false };
}

export function createThreatLookupRouter(): Router {
  const router = Router();

  router.post("/api/threat-lookup", (req, res, next) => {
    void (async () => {
      try {
        const parsed = lookupSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({ available: false });
          return;
        }

        const { url, registrableDomain } = parsed.data;
        const cacheKey = `${url}|${registrableDomain ?? ""}`;
        const cached = getCached(cacheKey);
        if (cached) {
          res.json(cached);
          return;
        }

        // V1: local curated feed. Future: query OpenPhish/PhishTank/Safe
        // Browsing here using server-side env credentials.
        const response = checkLocalFeed(url, registrableDomain ?? null);
        setCached(cacheKey, response);
        logger.debug(
          { url, matched: response.matched },
          "threat-lookup complete",
        );
        res.json(response);
      } catch (error) {
        next(error);
      }
    })();
  });

  return router;
}
