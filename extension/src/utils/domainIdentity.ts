// The `psl` package's "exports" map omits a "types" condition, so TS can't
// resolve its bundled declarations under bundler resolution. This ambient
// declaration (in a .d.ts consumed via tsconfig include) fixes that.
import psl from "psl";

/**
 * Domain identity module — the single source of truth for deciding whether a
 * hostname genuinely belongs to a claimed brand (docs/scamshield-rule-engine-changes.md §2–§7).
 *
 * Key principle: impersonation is judged on the REGISTRABLE DOMAIN, never on
 * whether the hostname merely contains a brand string. `accounts.google.com`
 * is official; `google.login.attacker.example` is not.
 */

// ---------------------------------------------------------------------------
// Brand registry (§3) — authoritative, exact registrable-domain matching only.
// ---------------------------------------------------------------------------

export interface BrandDefinition {
  id: string;
  names: string[];
  /** Verified official registrable domains. Exact match against PSL domain. */
  officialDomains: string[];
}

export const BRANDS: readonly BrandDefinition[] = [
  {
    id: "google",
    names: ["google", "gogle", "googel"],
    officialDomains: [
      "google.com",
      "google.co.in",
      "google.co.uk",
      "google.de",
      "youtube.com",
      "gmail.com",
    ],
  },
  {
    id: "facebook",
    names: ["facebook", "facebok", "facbook"],
    officialDomains: [
      "facebook.com",
      "fb.com",
      "instagram.com",
      "whatsapp.com",
      "meta.com",
    ],
  },
  {
    id: "paypal",
    names: ["paypal", "paypa1", "pay pal"],
    officialDomains: ["paypal.com"],
  },
  {
    id: "microsoft",
    names: ["microsoft", "micrsoft", "microsft"],
    officialDomains: [
      "microsoft.com",
      "live.com",
      "office.com",
      "outlook.com",
      "bing.com",
      "linkedin.com",
    ],
  },
  {
    id: "apple",
    names: ["apple", "aple"],
    officialDomains: ["apple.com", "icloud.com"],
  },
  {
    id: "amazon",
    names: ["amazon", "amazn"],
    officialDomains: ["amazon.com", "amazon.in", "amazon.co.uk", "primevideo.com"],
  },
  {
    id: "netflix",
    names: ["netflix", "netflx"],
    officialDomains: ["netflix.com"],
  },
  {
    id: "instagram",
    names: ["instagram", "instgram"],
    officialDomains: ["instagram.com"],
  },
  {
    id: "whatsapp",
    names: ["whatsapp", "whatspp"],
    officialDomains: ["whatsapp.com"],
  },
  {
    id: "linkedin",
    names: ["linkedin", "linkdin"],
    officialDomains: ["linkedin.com"],
  },
  {
    id: "coinbase",
    names: ["coinbase", "coinbse"],
    officialDomains: ["coinbase.com"],
  },
  {
    id: "binance",
    names: ["binance", "binane"],
    officialDomains: ["binance.com"],
  },
  {
    id: "steam",
    names: ["steam", "steamcommunity"],
    officialDomains: ["steampowered.com", "steamcommunity.com"],
  },
  {
    id: "wellsfargo",
    names: ["wellsfargo", "wells fargo"],
    officialDomains: ["wellsfargo.com"],
  },
  {
    id: "chase",
    names: ["chase"],
    officialDomains: ["chase.com"],
  },
  {
    id: "hsbc",
    names: ["hsbc"],
    officialDomains: ["hsbc.com"],
  },
  {
    id: "sbi",
    names: ["sbi", "statebank"],
    officialDomains: ["sbi.co.in", "onlinesbi.sbi"],
  },
  {
    id: "hdfcbank",
    names: ["hdfc", "hdfcbank"],
    officialDomains: ["hdfcbank.com"],
  },
  {
    id: "icicibank",
    names: ["icici", "icicibank"],
    officialDomains: ["icicibank.com"],
  },
  {
    id: "axisbank",
    names: ["axisbank"],
    officialDomains: ["axisbank.com"],
  },
];

// ---------------------------------------------------------------------------
// Domain relationship model (§2)
// ---------------------------------------------------------------------------

export type DomainRelationship =
  | "official"
  | "trusted-subdomain"
  | "brand-in-subdomain"
  | "lookalike"
  | "brand-in-path"
  | "unrelated";

export interface DomainIdentity {
  hostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  organizationDomain: string | null;

  detectedBrand?: string;
  matchedOfficialDomain?: string;

  relationship: DomainRelationship;

  normalizedRegistrableDomain?: string;
  /** 0..1 similarity to the matched official domain (1 = identical). */
  similarity?: number;
}

// ---------------------------------------------------------------------------
// PSL-based parsing (§1.2)
// ---------------------------------------------------------------------------

export function getRegistrableDomain(hostname: string): string | null {
  const parsed = psl.get(hostname);
  return typeof parsed === "string" ? parsed : null;
}

export function getPublicSuffix(hostname: string): string | null {
  const parsed = psl.parse(hostname);
  return typeof parsed.suffix === "string" ? parsed.suffix : null;
}

export function getOrganizationDomain(hostname: string): string | null {
  const parsed = psl.parse(hostname);
  return typeof parsed.domain === "string" ? parsed.domain : null;
}

// ---------------------------------------------------------------------------
// Official-domain check (§4)
// ---------------------------------------------------------------------------

export function findBrandByName(hostname: string): BrandDefinition | null {
  const lower = hostname.toLowerCase();
  for (const brand of BRANDS) {
    for (const name of brand.names) {
      // Word-boundary-ish match so "chase" doesn't hit "purchase".
      const pattern = new RegExp(`(^|[^a-z0-9])${name}([^a-z0-9]|$)`, "i");
      if (pattern.test(lower)) return brand;
    }
  }
  return null;
}

export function isOfficialBrandDomain(
  registrableDomain: string,
  brandDefinition: BrandDefinition,
): boolean {
  const lower = registrableDomain.toLowerCase();
  return brandDefinition.officialDomains.some((d) => d === lower);
}

// ---------------------------------------------------------------------------
// Homoglyph normalization + similarity (§7)
// ---------------------------------------------------------------------------

const HOMOGLYPHS: Array<[RegExp, string]> = [
  [/0/g, "o"],
  [/1/g, "l"],
  [/3/g, "e"],
  [/4/g, "a"],
  [/5/g, "s"],
  [/7/g, "t"],
  [/8/g, "b"],
  [/\$/g, "s"],
  [/@/g, "a"],
];

/** Strips hyphens/dots and applies homoglyph substitutions. */
export function normalizeDomainLabel(label: string): string {
  let out = label.toLowerCase().replaceAll("-", "").replaceAll(".", "");
  for (const [from, to] of HOMOGLYPHS) out = out.replace(from, to);
  return out;
}

/**
 * Levenshtein-based similarity in [0, 1].
 * Deterministic and dependency-free — adequate for short domain labels.
 */
export function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const m = a.length;
  const n = b.length;
  if (m === 0 || n === 0) return 0;
  let prev: number[] = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const curr: number[] = new Array<number>(n + 1).fill(0);
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    prev = curr;
  }
  return 1 - (prev[n] ?? 0) / Math.max(m, n);
}

/** Configurable threshold — tuned by tests, not hard-coded magic (§7). */
export const LOOKALIKE_HIGH_SIMILARITY = 0.85;
export const LOOKALIKE_MODERATE_SIMILARITY = 0.7;

// ---------------------------------------------------------------------------
// The classifier (§5, §6, §7)
// ---------------------------------------------------------------------------

export function classifyDomain(hostname: string): DomainIdentity {
  const lower = hostname.toLowerCase();
  const registrableDomain = getRegistrableDomain(lower);
  const publicSuffix = getPublicSuffix(lower);
  const organizationDomain = getOrganizationDomain(lower);

  const base: DomainIdentity = {
    hostname: lower,
    registrableDomain,
    publicSuffix,
    organizationDomain,
    relationship: "unrelated",
  };

  // IP hosts / unparseable hostnames have no brand relationship.
  if (!registrableDomain || /^\d{1,3}(\.\d{1,3}){3}$/.test(lower)) {
    return base;
  }

  const brand = findBrandByName(lower);

  // §7 — lookalike evaluation on the registrable domain's first label.
  // Runs even when no brand name appears literally in the hostname, so
  // homoglyph domains like g00gle.example are caught (§1.3).
  const regLower = registrableDomain.toLowerCase();
  const firstLabel = regLower.split(".")[0] ?? "";
  let bestMatch: { domain: string; score: number; brand: BrandDefinition } | null =
    null;
  for (const candidateBrand of BRANDS) {
    for (const officialDomain of candidateBrand.officialDomains) {
      const officialFirstLabel = officialDomain.split(".")[0] ?? "";
      // Skip trivially short labels — "sbi" vs anything is too noisy.
      if (officialFirstLabel.length < 5) continue;
      const score = similarity(
        normalizeDomainLabel(firstLabel),
        normalizeDomainLabel(officialFirstLabel),
      );
      if (!bestMatch || score > bestMatch.score) {
        bestMatch = { domain: officialDomain, score, brand: candidateBrand };
      }
    }
  }

  // Official-domain check takes precedence over lookalike scoring.
  if (brand && isOfficialBrandDomain(registrableDomain, brand)) {
    return {
      ...base,
      detectedBrand: brand.id,
      matchedOfficialDomain: registrableDomain,
      relationship: registrableDomain === lower ? "official" : "trusted-subdomain",
    };
  }

  // §6 step 5 — brand appears in an attacker-controlled subdomain
  // (e.g. google.login.attacker.example).
  const primaryName = brand?.names[0] ?? "";
  const brandInSubdomainOnly =
    brand !== null &&
    primaryName !== "" &&
    !regLower.includes(primaryName) &&
    lower.includes(primaryName);

  if (brandInSubdomainOnly) {
    return { ...base, detectedBrand: brand!.id, relationship: "brand-in-subdomain" };
  }

  if (bestMatch && bestMatch.score >= LOOKALIKE_MODERATE_SIMILARITY) {
    return {
      ...base,
      detectedBrand: bestMatch.brand.id,
      matchedOfficialDomain: bestMatch.domain,
      relationship: "lookalike",
      normalizedRegistrableDomain: normalizeDomainLabel(firstLabel),
      similarity: bestMatch.score,
    };
  }

  // Brand keyword embedded in the registrable domain itself on a
  // non-official domain (e.g. paypal-support.com, google-login.net).
  // This is the classic "brand + phishing keyword" registration pattern.
  if (brand && regLower.includes(primaryName)) {
    const PHISHING_KEYWORDS = [
      "support",
      "login",
      "secure",
      "verify",
      "account",
      "update",
      "billing",
      "help",
      "service",
      "recover",
      "unlock",
      "confirm",
      "signin",
      "alert",
      "notice",
      "case",
      "id",
    ];
    const hasPhishKeyword = PHISHING_KEYWORDS.some((kw) =>
      regLower.includes(kw),
    );
    if (hasPhishKeyword) {
      return {
        ...base,
        detectedBrand: brand.id,
        relationship: "lookalike",
        matchedOfficialDomain: brand.officialDomains[0],
        similarity: LOOKALIKE_MODERATE_SIMILARITY,
      };
    }
  }

  // No brand relationship found.
  return base;
}
