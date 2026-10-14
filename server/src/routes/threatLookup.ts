import { Router } from "express";
import { z } from "zod";
import { logger } from "../lib/logger.js";
import {
  getFeedStatus,
  lookupFeed,
  startFeedRefresh,
  stopFeedRefresh,
} from "../services/openPhishFeed.js";
import { lookupGoogleSafeBrowsing } from "../services/safeBrowsing.js";
import type { SafeBrowsingStatus } from "@scamshield/shared";

/**
 * POST /api/threat-lookup (spec §4–§6)
 *
 * Provider-neutral threat-intelligence proxy. Provider API keys live ONLY
 * in server env — never in the extension.
 *
 * INVARIANT (spec §2, §21 rules 2 & 10): a lookup that could not be completed
 * MUST surface `available: false`. Returning `available: true,
 * NO_KNOWN_THREAT` while every provider was down is a false "we checked and
 * it is clean" assertion, and it poisons both the server and client caches.
 */

const lookupSchema = z.object({
  url: z.string().url(),
  registrableDomain: z.string().nullable().optional(),
});

export interface ThreatLookupResponse {
  /** True only when at least one authoritative provider actually answered. */
  available: boolean;
  matched: boolean;
  status: "MATCH" | "NO_KNOWN_THREAT" | "UNAVAILABLE";
  /** Explicit per-provider state so the UI can explain degraded coverage. */
  safeBrowsingStatus: SafeBrowsingStatus;
  threatType?: string;
  confidence?: "confirmed" | "high" | "medium";
  source?: string;
  reason?: string;
}

// ---------------------------------------------------------------------------
// In-memory cache (server-side layer of spec §7)
// ---------------------------------------------------------------------------

const CACHE_TTL_MATCHED_MS = 24 * 60 * 60 * 1000;
const CACHE_TTL_NEGATIVE_MS = 30 * 60 * 1000;
/**
 * An UNAVAILABLE result is cached only briefly. A long TTL would turn a
 * transient outage into a persistent false negative.
 */
const CACHE_TTL_UNAVAILABLE_MS = 60 * 1000;
/** Hard cap so a long-running process cannot leak memory via unique URLs. */
const CACHE_MAX_ENTRIES = 5_000;

const cache = new Map<
  string,
  { response: ThreatLookupResponse; expiresAt: number }
>();

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
  // Opportunistic eviction — the Map would otherwise retain expired entries
  // for URLs that are never revisited, for the lifetime of the process.
  if (cache.size >= CACHE_MAX_ENTRIES) {
    const now = Date.now();
    for (const [k, v] of cache) {
      if (now > v.expiresAt) cache.delete(k);
    }
    if (cache.size >= CACHE_MAX_ENTRIES) {
      const oldest = cache.keys().next();
      if (!oldest.done) cache.delete(oldest.value);
    }
  }
  const ttl = !response.available
    ? CACHE_TTL_UNAVAILABLE_MS
    : response.matched
      ? CACHE_TTL_MATCHED_MS
      : CACHE_TTL_NEGATIVE_MS;
  cache.set(key, { response, expiresAt: Date.now() + ttl });
}

// ---------------------------------------------------------------------------
// Local curated feed (works with zero external dependencies).
// Format: one URL/domain pattern per line, `*` wildcard prefix supported.
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

function hostOf(url: string, fallback: string | null): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return fallback?.toLowerCase() ?? "";
  }
}

/** Consult the OpenPhish feed, then the curated static list. */
function checkLocalFeeds(
  url: string,
  registrableDomain: string | null,
): ThreatLookupResponse | null {
  // 1. OpenPhish feed (live phishing URLs, refreshed on an interval).
  const feedHit = lookupFeed(url);
  if (feedHit) {
    return {
      available: true,
      matched: true,
      status: "MATCH",
      safeBrowsingStatus: "NO_KNOWN_THREAT",
      threatType: feedHit.threatType,
      confidence: feedHit.confidence,
      source: "openphish",
    };
  }

  // 2. Curated static fallback for known brand-abuse domains.
  const host = hostOf(url, registrableDomain);
  const matched =
    (registrableDomain !== null && LOCAL_FEED.has(registrableDomain.toLowerCase())) ||
    LOCAL_FEED.has(host);

  if (matched) {
    return {
      available: true,
      matched: true,
      status: "MATCH",
      safeBrowsingStatus: "NO_KNOWN_THREAT",
      threatType: "phishing",
      confidence: "high",
      source: "scamshield-local-feed",
    };
  }

  return null;
}

export function startThreatFeed(): void {
  startFeedRefresh();
}

export function stopThreatFeed(): void {
  stopFeedRefresh();
}

export function createThreatLookupRouter(): Router {
  const router = Router();

  router.post("/api/threat-lookup", (req, res, next) => {
    void (async () => {
      try {
        const parsed = lookupSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({
            available: false,
            matched: false,
            status: "UNAVAILABLE",
            safeBrowsingStatus: "UNKNOWN",
            reason: "Invalid lookup request.",
          } satisfies ThreatLookupResponse);
          return;
        }

        const { url, registrableDomain } = parsed.data;
        const cacheKey = `${url}|${registrableDomain ?? ""}`;
        const cached = getCached(cacheKey);
        if (cached) {
          res.json(cached);
          return;
        }

        // Google Safe Browsing is checked first server-side.
        const sb = await lookupGoogleSafeBrowsing(url);
        if (sb.status === "KNOWN_MALICIOUS" && sb.matched) {
          const response = {
            available: true,
            matched: true,
            status: "MATCH",
            safeBrowsingStatus: "KNOWN_MALICIOUS",
            ...(sb.threatType ? { threatType: sb.threatType } : {}),
            confidence: sb.confidence ?? "confirmed",
            source: sb.source ?? "googlesafebrowsing",
          } satisfies ThreatLookupResponse;
          setCached(cacheKey, response);
          logger.debug(
            { registrableDomain: registrableDomain ?? undefined, matched: true },
            "threat-lookup complete",
          );
          res.json(response);
          return;
        }

        // Safe Browsing miss or outage falls through to the local feeds.
        const feedMatch = checkLocalFeeds(url, registrableDomain ?? null);
        if (feedMatch) {
          setCached(cacheKey, feedMatch);
          res.json(feedMatch);
          return;
        }

        // Nothing matched. The honest answer depends on whether any provider
        // actually gave us coverage:
        //  - Safe Browsing answered  -> "no known threat" (not "safe").
        //  - OpenPhish loaded & fresh-> "no known threat".
        //  - Otherwise               -> UNAVAILABLE, never a clean bill.
        const feedState = getFeedStatus();
        const sbAnswered = sb.status === "NO_KNOWN_THREAT";
        const feedUsable = feedState.loaded && !feedState.stale;

        const response: ThreatLookupResponse =
          sbAnswered || feedUsable
            ? {
                available: true,
                matched: false,
                status: "NO_KNOWN_THREAT",
                safeBrowsingStatus: sb.status,
              }
            : {
                available: false,
                matched: false,
                status: "UNAVAILABLE",
                safeBrowsingStatus: sb.status,
                reason:
                  sb.reason ??
                  "Threat intelligence providers were unavailable; this result is inconclusive.",
              };

        setCached(cacheKey, response);
        logger.debug(
          {
            registrableDomain: registrableDomain ?? undefined,
            matched: false,
            available: response.available,
            safeBrowsingStatus: response.safeBrowsingStatus,
            feedEntries: feedState.entryCount,
          },
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
