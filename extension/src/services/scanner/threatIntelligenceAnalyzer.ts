import type { RiskVerdict } from "@shared/index";

/**
 * Threat-intelligence layer (spec §4–§7).
 *
 * Provider-neutral interface. The default provider calls the ScamShield
 * backend (`/api/threat-lookup`), which hides provider secrets and caches
 * results — no third-party API key ever ships in the extension.
 *
 * CRITICAL RULE: a failed/unavailable lookup must NEVER be interpreted as
 * "safe". Callers receive `available: false` and must set coverage
 * accordingly (§3: unknown ≠ safe).
 */

export interface ThreatIntelLookupInput {
  normalizedUrl: string;
  registrableDomain: string | null;
}

export interface ThreatIntelMatch {
  available: boolean;
  matched: boolean;

  threatType?: string;
  confidence?: "confirmed" | "high" | "medium";
  source?: string;

  checkedAt: number;
  expiresAt?: number;
}

export interface ThreatEvidence {
  provider: string;
  verdict: "malicious" | "benign" | "unknown";
  threatType?: string;
  checkedAt: number;
}

export interface ThreatIntelProvider {
  name: string;
  lookupUrl(input: ThreatIntelLookupInput): Promise<ThreatIntelMatch>;
}

// ---------------------------------------------------------------------------
// Cache (§7) — chrome.storage.local backed, TTL by verdict class.
// ---------------------------------------------------------------------------

interface CachedThreatResult {
  normalizedUrl: string;
  registrableDomain: string | null;
  matched: boolean;
  threatType?: string;
  provider: string;
  checkedAt: number;
  expiresAt: number;
}

const CACHE_KEY = "threatCache";
const CACHE_LIMIT = 500;

/** Confirmed malicious lives long; negatives are short; failures never cached. */
const TTL_MALICIOUS_MS = 24 * 60 * 60 * 1000; // 24 h
const TTL_NEGATIVE_MS = 30 * 60 * 1000; // 30 min

function cacheStorage(): chrome.storage.StorageArea {
  return chrome.storage.local;
}

async function readCache(key: string): Promise<CachedThreatResult | null> {
  const result = await cacheStorage().get(CACHE_KEY);
  const stored = result[CACHE_KEY];
  if (!Array.isArray(stored)) return null;
  const entry = (stored as CachedThreatResult[]).find((e) => e.normalizedUrl === key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) return null; // expired → treat as miss
  return entry;
}

async function writeCache(entry: CachedThreatResult): Promise<void> {
  const result = await cacheStorage().get(CACHE_KEY);
  const stored = Array.isArray(result[CACHE_KEY])
    ? (result[CACHE_KEY] as CachedThreatResult[])
    : [];
  const next = [
    entry,
    ...stored.filter((e) => e.normalizedUrl !== entry.normalizedUrl),
  ].slice(0, CACHE_LIMIT);
  await cacheStorage().set({ [CACHE_KEY]: next });
}

export async function clearThreatCache(): Promise<void> {
  await cacheStorage().set({ [CACHE_KEY]: [] });
}

// ---------------------------------------------------------------------------
// Backend-backed provider
// ---------------------------------------------------------------------------

export interface BackendThreatProviderOptions {
  baseUrl: string;
  timeoutMs?: number;
}

/**
 * Calls POST /api/threat-lookup on the ScamShield backend.
 * Response contract:
 *   { available: true, matched: boolean, threatType?, confidence?, source? }
 *   { available: false }            ← provider outage; never treated as safe
 */
export class BackendThreatProvider implements ThreatIntelProvider {
  name = "scamshield-backend";

  constructor(private readonly options: BackendThreatProviderOptions) {}

  async lookupUrl(input: ThreatIntelLookupInput): Promise<ThreatIntelMatch> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 5_000);
    try {
      const response = await fetch(
        `${this.options.baseUrl.replace(/\/$/, "")}/api/threat-lookup`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url: input.normalizedUrl,
            registrableDomain: input.registrableDomain,
          }),
          signal: controller.signal,
        },
      );
      if (!response.ok) {
        return unavailable();
      }
      const body = (await response.json()) as {
        available?: boolean;
        matched?: boolean;
        threatType?: string;
        confidence?: string;
        source?: string;
      };
      if (body.available !== true) return unavailable();

      const now = Date.now();
      return {
        available: true,
        matched: body.matched === true,
        threatType: body.threatType,
        confidence:
          body.confidence === "confirmed" || body.confidence === "high"
            ? body.confidence
            : "medium",
        source: body.source ?? this.name,
        checkedAt: now,
      };
    } catch {
      // Network failure / timeout / abort → unknown, NOT benign (§37).
      return unavailable();
    } finally {
      clearTimeout(timer);
    }
  }
}

function unavailable(): ThreatIntelMatch {
  return { available: false, matched: false, checkedAt: Date.now() };
}

// ---------------------------------------------------------------------------
// Bundled local feed (§4): always available, zero network, zero config.
// Mirrors the server-side curated feed so threat intel works offline.
// ---------------------------------------------------------------------------

const LOCAL_FEED = new Set<string>([
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

export class LocalFeedProvider implements ThreatIntelProvider {
  name = "scamshield-local-feed";

  async lookupUrl(input: ThreatIntelLookupInput): Promise<ThreatIntelMatch> {
    const host = (() => {
      try {
        return new URL(input.normalizedUrl).hostname.toLowerCase();
      } catch {
        return input.registrableDomain?.toLowerCase() ?? "";
      }
    })();

    const matched =
      (input.registrableDomain !== null &&
        LOCAL_FEED.has(input.registrableDomain.toLowerCase())) ||
      LOCAL_FEED.has(host);

    return {
      available: true,
      matched,
      threatType: matched ? "phishing" : undefined,
      confidence: matched ? "high" : undefined,
      source: this.name,
      checkedAt: Date.now(),
    };
  }
}

/**
 * Composite provider: tries the backend first (richer feeds), falls back to
 * the bundled local feed so threat intel is ALWAYS available.
 */
export class CompositeThreatProvider implements ThreatIntelProvider {
  name = "scamshield-composite";

  constructor(private readonly providers: ThreatIntelProvider[]) {}

  async lookupUrl(input: ThreatIntelLookupInput): Promise<ThreatIntelMatch> {
    for (const provider of this.providers) {
      const result = await provider.lookupUrl(input);
      if (result.available) return result;
    }
    return unavailable();
  }
}

// ---------------------------------------------------------------------------
// Facade used by the scan pipeline
// ---------------------------------------------------------------------------

export interface ThreatLookupResult {
  match: ThreatIntelMatch;
  /** True when served from the local cache. */
  fromCache: boolean;
  evidence: ThreatEvidence[];
}

export async function lookupThreatIntelligence(
  input: ThreatIntelLookupInput,
  provider: ThreatIntelProvider | null,
): Promise<ThreatLookupResult> {
  if (!provider) {
    return { match: unavailable(), fromCache: false, evidence: [] };
  }

  const cacheKey = input.normalizedUrl;
  const cached = await readCache(cacheKey);
  if (cached) {
    return {
      match: {
        available: true,
        matched: cached.matched,
        threatType: cached.threatType,
        confidence: cached.matched ? "confirmed" : undefined,
        source: cached.provider,
        checkedAt: cached.checkedAt,
        expiresAt: cached.expiresAt,
      },
      fromCache: true,
      evidence: [
        {
          provider: cached.provider,
          verdict: cached.matched ? "malicious" : "benign",
          threatType: cached.threatType,
          checkedAt: cached.checkedAt,
        },
      ],
    };
  }

  const match = await provider.lookupUrl(input);
  if (!match.available) {
    // §7: provider unavailable → never cache as safe.
    return { match, fromCache: false, evidence: [] };
  }

  const now = Date.now();
  await writeCache({
    normalizedUrl: cacheKey,
    registrableDomain: input.registrableDomain,
    matched: match.matched,
    threatType: match.threatType,
    provider: match.source ?? provider.name,
    checkedAt: now,
    expiresAt: now + (match.matched ? TTL_MALICIOUS_MS : TTL_NEGATIVE_MS),
  });

  return {
    match,
    fromCache: false,
    evidence: [
      {
        provider: match.source ?? provider.name,
        verdict: match.matched ? "malicious" : "benign",
        threatType: match.threatType,
        checkedAt: now,
      },
    ],
  };
}

/**
 * Verdict contribution (§6): a confirmed/high-confidence malicious match
 * produces DANGEROUS regardless of local heuristics.
 */
export function threatVerdictOverride(match: ThreatIntelMatch): RiskVerdict | null {
  if (!match.available || !match.matched) return null;
  if (match.confidence === "confirmed" || match.confidence === "high") {
    return "dangerous";
  }
  return "high_risk";
}
