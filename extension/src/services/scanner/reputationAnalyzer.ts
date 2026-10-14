import type { DomainSignals } from "@shared/index";
import type { ScanContext } from "./ruleEngine";

interface CachedDomainResult {
  expiresAt: number;
  result: DomainSignals;
}

const cache = new Map<string, CachedDomainResult>();
const CACHE_TTL_MS = 60 * 60 * 1000;
/** Unavailable answers are cached only briefly — a transient RDAP outage must
 *  not suppress fresh lookups, but every scan retrying a dead endpoint would
 *  hammer the provider and slow scans to the timeout. */
const UNAVAILABLE_TTL_MS = 60 * 1000;
/** Hard cap so a long-lived worker cannot leak entries per unique domain. */
const CACHE_MAX_ENTRIES = 500;
const LOOKUP_TIMEOUT_MS = 3_000;

function pruneCache(): void {
  if (cache.size < CACHE_MAX_ENTRIES) return;
  const now = Date.now();
  for (const [key, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(key);
  }
  while (cache.size >= CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next();
    if (oldest.done) break;
    cache.delete(oldest.value);
  }
}

function remember(domain: string, result: DomainSignals, ttlMs: number): void {
  pruneCache();
  cache.set(domain, { expiresAt: Date.now() + ttlMs, result });
}

export async function collectDomainSignals(
  context: Pick<ScanContext, "urlSignals">,
): Promise<DomainSignals> {
  // IP literals have no RDAP *domain* record (they live under /ip/, which we
  // do not query) — skip the doomed fetch instead of burning the timeout.
  if (context.urlSignals.isIpHost) {
    return unavailable("IP-literal hosts have no domain registration record.");
  }
  const domain = context.urlSignals.registrableDomain.toLowerCase();
  const cached = cache.get(domain);
  if (cached && cached.expiresAt > Date.now()) return cached.result;

  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const response = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { signal: controller.signal },
    );
    if (!response.ok) {
      const result = unavailable("RDAP did not provide domain metadata.");
      remember(domain, result, UNAVAILABLE_TTL_MS);
      return result;
    }

    const payload = (await response.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{
        roles?: string[];
        vcardArray?: [string, Array<[string, string, unknown, string]>];
      }>;
    };
    const registrationEvent = payload.events?.find(
      (event) => event.eventAction?.toLowerCase() === "registration",
    );
    const registeredAt = registrationEvent?.eventDate
      ? Date.parse(registrationEvent.eventDate)
      : Number.NaN;
    const registrarEntity = payload.entities?.find((entity) =>
      entity.roles?.some((role) => role.toLowerCase() === "registrar"),
    );
    const registrar = extractRegistrar(registrarEntity?.vcardArray);
    const result: DomainSignals = {
      available: true,
      domainAgeDays: Number.isFinite(registeredAt)
        ? Math.max(0, Math.floor((Date.now() - registeredAt) / 86_400_000))
        : undefined,
      registrar,
      source: "rdap",
    };
    remember(domain, result, CACHE_TTL_MS);
    return result;
  } catch {
    const result = unavailable("RDAP lookup unavailable.");
    remember(domain, result, UNAVAILABLE_TTL_MS);
    return result;
  } finally {
    globalThis.clearTimeout(timer);
  }
}

function unavailable(reason: string): DomainSignals {
  return { available: false, reason };
}

function extractRegistrar(
  vcardArray: [string, Array<[string, string, unknown, string]>] | undefined,
): string | null {
  const fields = vcardArray?.[1] ?? [];
  const name = fields.find((field) => field[0].toLowerCase() === "fn");
  return typeof name?.[3] === "string" && name[3].length <= 200 ? name[3] : null;
}
