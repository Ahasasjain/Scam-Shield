/**
 * Google Safe Browsing lookup (spec §2).
 *
 * CRITICAL SEMANTICS (spec §2, §21 rule 2):
 * A "no match" is NOT proof that a website is safe, and a provider outage is
 * NOT the same as a clean result. This module therefore returns one of four
 * EXPLICIT states and never `null`:
 *
 *   KNOWN_MALICIOUS    — provider returned a threat match. Strong deterministic
 *                        evidence; must never be overridden by AI.
 *   NO_KNOWN_THREAT    — provider responded and reported nothing. "Nothing
 *                        known", NOT "safe".
 *   LOOKUP_UNAVAILABLE — provider errored/timed out/rate-limited/malformed, or
 *                        is not configured. Callers MUST surface this as
 *                        unknown, never as clean.
 *   UNKNOWN            — response was well-formed but unusable.
 */

import { z } from "zod";
import { logger } from "../lib/logger.js";
import type { SafeBrowsingStatus } from "@scamshield/shared";

export interface SafeBrowsingLookupResult {
  /** True only when the provider actually answered a well-formed request. */
  available: boolean;
  matched: boolean;
  status: SafeBrowsingStatus;
  threatType?: string;
  confidence?: "confirmed" | "high" | "medium";
  source?: string;
  /** Populated when status is LOOKUP_UNAVAILABLE — never user-facing secrets. */
  reason?: string;
}

const GOOGLE_SAFE_BROWSING_API =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const DEFAULT_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];
const LOOKUP_TIMEOUT_MS = 4_000;

/** Validates the provider response instead of trusting a bare cast (spec §21 rule 12). */
const safeBrowsingResponseSchema = z.object({
  matches: z
    .array(
      z.object({
        threatType: z.string().optional(),
        platformType: z.string().optional(),
        threatEntryType: z.string().optional(),
      }),
    )
    .optional(),
});

function unavailable(reason: string): SafeBrowsingLookupResult {
  return {
    available: false,
    matched: false,
    status: "LOOKUP_UNAVAILABLE",
    source: "googlesafebrowsing",
    reason,
  };
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim() !== "") return value;
  }
  return undefined;
}

export async function lookupGoogleSafeBrowsing(
  url: string,
): Promise<SafeBrowsingLookupResult> {
  // `??` is not enough: dotenv materialises an unset-but-present env var as
  // the empty string, which is not nullish. Take the first NON-EMPTY value so
  // a blank GOOGLE_SAFEBROWSING_API_KEY does not mask a valid GCSB_API_KEY.
  const apiKey =
    firstNonEmpty(
      process.env["GOOGLE_SAFEBROWSING_API_KEY"],
      process.env["GCSB_API_KEY"],
    ) ?? "";
  // Not configured is an OUTAGE of coverage, not a clean bill of health.
  if (!apiKey) return unavailable("Google Safe Browsing is not configured.");

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, LOOKUP_TIMEOUT_MS);
  try {
    const response = await fetch(
      `${GOOGLE_SAFE_BROWSING_API}?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "scamshield", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: DEFAULT_THREAT_TYPES,
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
        signal: controller.signal,
      },
    );

    if (!response.ok) {
      const reason =
        response.status === 429
          ? "Google Safe Browsing rate limit reached."
          : response.status === 401 || response.status === 403
            ? "Google Safe Browsing rejected the configured key."
            : `Google Safe Browsing responded with status ${response.status}.`;
      logger.warn({ status: response.status }, reason);
      return unavailable(reason);
    }

    // Malformed JSON throws here and is handled by the catch below.
    const raw: unknown = await response.json();
    const parsed = safeBrowsingResponseSchema.safeParse(raw);
    if (!parsed.success) {
      logger.warn("Google Safe Browsing returned an unrecognised payload shape");
      return {
        available: false,
        matched: false,
        status: "UNKNOWN",
        source: "googlesafebrowsing",
        reason: "Unrecognised Safe Browsing response.",
      };
    }

    const first = parsed.data.matches?.[0];
    if (!first) {
      // Well-formed, nothing reported. Still NOT proof of safety.
      return {
        available: true,
        matched: false,
        status: "NO_KNOWN_THREAT",
        source: "googlesafebrowsing",
      };
    }

    // Do not fabricate a threat type: an absent value stays absent, and the
    // verdict path must not treat this as a confirmed phishing verdict.
    const threatType = first.threatType?.toLowerCase();

    return {
      available: true,
      matched: true,
      status: "KNOWN_MALICIOUS",
      ...(threatType ? { threatType } : {}),
      confidence: "confirmed",
      source: "googlesafebrowsing",
    };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    logger.warn(
      { aborted },
      "Google Safe Browsing lookup failed; treating as unavailable",
    );
    return unavailable(
      aborted
        ? "Google Safe Browsing lookup timed out."
        : "Google Safe Browsing lookup failed.",
    );
  } finally {
    clearTimeout(timer);
  }
}
