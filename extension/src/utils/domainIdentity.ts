// The `psl` package's "exports" map omits a "types" condition, so TS can't
// resolve its bundled declarations under bundler resolution. This ambient
// declaration (in a .d.ts consumed via tsconfig include) fixes that.
import psl from "psl";

/**
 * Domain identity module — the single source of truth for deciding whether a
 * hostname genuinely belongs to a claimed brand (docs/rule-engine.md).
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
    names: ["facebook", "fakebook", "facebok", "facbook"],
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
  {
    id: "x",
    names: ["twitter", "twiter"],
    officialDomains: ["x.com", "twitter.com"],
  },
  {
    id: "yahoo",
    names: ["yahoo", "yaho"],
    officialDomains: ["yahoo.com"],
  },
  {
    id: "tiktok",
    names: ["tiktok", "tiktock"],
    officialDomains: ["tiktok.com"],
  },
  {
    id: "snapchat",
    names: ["snapchat", "snapchatt"],
    officialDomains: ["snapchat.com"],
  },
  {
    id: "pinterest",
    names: ["pinterest", "pintrest"],
    officialDomains: ["pinterest.com"],
  },
  {
    id: "reddit",
    names: ["reddit", "reditt"],
    officialDomains: ["reddit.com"],
  },
  {
    id: "discord",
    names: ["discord", "disscord"],
    officialDomains: ["discord.com"],
  },
  {
    id: "telegram",
    names: ["telegram", "telegrm"],
    officialDomains: ["telegram.org", "t.me"],
  },
  {
    id: "adobe",
    names: ["adobe", "adob"],
    officialDomains: ["adobe.com"],
  },
  {
    id: "dropbox",
    names: ["dropbox", "dropbx"],
    officialDomains: ["dropbox.com"],
  },
  {
    id: "github",
    names: ["github", "githib"],
    officialDomains: ["github.com"],
  },
  {
    id: "zoom",
    names: ["zoom"],
    officialDomains: ["zoom.us"],
  },
  {
    id: "slack",
    names: ["slack"],
    officialDomains: ["slack.com"],
  },
  {
    id: "samsung",
    names: ["samsung", "samsng"],
    officialDomains: ["samsung.com"],
  },
  {
    id: "ebay",
    names: ["ebay"],
    officialDomains: ["ebay.com"],
  },
  {
    id: "walmart",
    names: ["walmart", "wallmart"],
    officialDomains: ["walmart.com"],
  },
  {
    id: "alibaba",
    names: ["alibaba", "aliexpress"],
    officialDomains: ["alibaba.com", "aliexpress.com"],
  },
  {
    id: "flipkart",
    names: ["flipkart", "flipkrt"],
    officialDomains: ["flipkart.com"],
  },
  {
    id: "phonepe",
    names: ["phonepe", "phonepay"],
    officialDomains: ["phonepe.com"],
  },
  {
    id: "paytm",
    names: ["paytm", "paytmm"],
    officialDomains: ["paytm.com"],
  },
  {
    id: "bankofamerica",
    names: ["bankofamerica", "bankamerica"],
    officialDomains: ["bankofamerica.com"],
  },
  {
    id: "citi",
    names: ["citi", "citibank"],
    officialDomains: ["citi.com", "citibank.com"],
  },
  {
    id: "capitalone",
    names: ["capitalone", "capitolone"],
    officialDomains: ["capitalone.com"],
  },
  {
    id: "americanexpress",
    names: ["americanexpress", "amex"],
    officialDomains: ["americanexpress.com"],
  },
  {
    id: "venmo",
    names: ["venmo"],
    officialDomains: ["venmo.com"],
  },
  {
    id: "cashapp",
    names: ["cashapp"],
    officialDomains: ["cash.app"],
  },
  {
    id: "zelle",
    names: ["zelle", "zellepay"],
    officialDomains: ["zellepay.com"],
  },
  {
    id: "kraken",
    names: ["kraken"],
    officialDomains: ["kraken.com"],
  },
  {
    id: "metamask",
    names: ["metamask", "metemask"],
    officialDomains: ["metamask.io"],
  },
  {
    id: "ledger",
    names: ["ledger"],
    officialDomains: ["ledger.com"],
  },
  {
    id: "disney",
    names: ["disney", "disny"],
    officialDomains: ["disney.com", "disneyplus.com"],
  },
  {
    id: "hbo",
    names: ["hbo", "hbomax", "max"],
    officialDomains: ["max.com", "hbo.com"],
  },
  {
    id: "spotify",
    names: ["spotify", "spotfy"],
    officialDomains: ["spotify.com"],
  },
  {
    id: "twitch",
    names: ["twitch", "twich"],
    officialDomains: ["twitch.tv"],
  },
  {
    id: "roblox",
    names: ["roblox", "roblok"],
    officialDomains: ["roblox.com"],
  },
  {
    id: "epicgames",
    names: ["epicgames", "epic"],
    officialDomains: ["epicgames.com"],
  },
  {
    id: "playstation",
    names: ["playstation", "playstaion"],
    officialDomains: ["playstation.com"],
  },
  {
    id: "xbox",
    names: ["xbox"],
    officialDomains: ["xbox.com"],
  },
  {
    id: "minecraft",
    names: ["minecraft", "minecarft"],
    officialDomains: ["minecraft.net", "mojang.com"],
  },
  {
    id: "nintendo",
    names: ["nintendo", "nintento"],
    officialDomains: ["nintendo.com"],
  },
  {
    id: "fedex",
    names: ["fedex", "fedx"],
    officialDomains: ["fedex.com"],
  },
  {
    id: "ups",
    names: ["ups"],
    officialDomains: ["ups.com"],
  },
  {
    id: "usps",
    names: ["usps"],
    officialDomains: ["usps.com"],
  },
  {
    id: "dhl",
    names: ["dhl"],
    officialDomains: ["dhl.com"],
  },
  {
    id: "irs",
    names: ["irs"],
    officialDomains: ["irs.gov"],
  },
  {
    id: "incometaxindia",
    names: ["incometax"],
    officialDomains: ["incometax.gov.in"],
  },
  {
    id: "proton",
    names: ["proton", "protonmail"],
    officialDomains: ["proton.me", "protonmail.com"],
  },
  {
    id: "onlyfans",
    names: ["onlyfans", "onlyfan"],
    officialDomains: ["onlyfans.com"],
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

/**
 * Finds the brand that owns a registrable domain.
 *
 * Several properties appear in more than one registry (instagram.com and
 * whatsapp.com sit under both `facebook` and their own brand; linkedin.com
 * under both `microsoft` and `linkedin`). Reporting the conglomerate would
 * label Instagram as "Facebook" in the UI, so the brand whose own name
 * appears in the domain wins. Falls back to the first registrant.
 */
export function findOwningBrand(registrableDomain: string): BrandDefinition | null {
  const owners = BRANDS.filter((candidate) =>
    isOfficialBrandDomain(registrableDomain, candidate),
  );
  if (owners.length === 0) return null;
  if (owners.length === 1) return owners[0]!;

  const label = registrableDomain.toLowerCase().split(".")[0] ?? "";
  const specific = owners.find((candidate) =>
    candidate.names.some(
      (name) => label === name || label.startsWith(name) || label.includes(name),
    ),
  );
  return specific ?? owners[0]!;
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

export function classifyDomain(hostname: string, pathname = ""): DomainIdentity {
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

  // §4 — Official-domain check takes precedence over ALL lookalike scoring.
  //
  // This must compare the registrable domain against EVERY brand's official
  // domains, NOT only the brand whose name happens to appear in the hostname.
  // Two reasons:
  //
  // 1. A brand's own official domain is trivially "similar" to itself. The
  //    lookalike loop below scores similarity 1.0 for any registrable domain
  //    whose first label equals a brand's official first label — which would
  //    otherwise flag youtube.com (an official google property, but with no
  //    "google" in the hostname) as a lookalike of google.com.
  // 2. Brands legitimately own domains whose name differs from the brand
  //    string (gmail.com, icloud.com, primevideo.com, steampowered.com...).
  //
  // A registrable domain that is on the allowlist can never be a lookalike.
  const officialBrand = findOwningBrand(registrableDomain);
  if (officialBrand) {
    return {
      ...base,
      detectedBrand: officialBrand.id,
      matchedOfficialDomain: registrableDomain,
      relationship: registrableDomain === lower ? "official" : "trusted-subdomain",
    };
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
      // Defensive: a brand never impersonates itself.
      if (officialDomain.toLowerCase() === regLower) continue;
      const score = similarity(
        normalizeDomainLabel(firstLabel),
        normalizeDomainLabel(officialFirstLabel),
      );
      if (!bestMatch || score > bestMatch.score) {
        bestMatch = { domain: officialDomain, score, brand: candidateBrand };
      }
    }
  }

  // §6 step 5 — brand appears in an attacker-controlled subdomain
  // (e.g. google.login.attacker.example).
  const matchedSubdomainName =
    brand?.names.find((name) => !regLower.includes(name) && lower.includes(name)) ?? "";
  const brandInSubdomainOnly = matchedSubdomainName !== "";

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
  const primaryName = brand?.names[0] ?? "";
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
    const hasPhishKeyword = PHISHING_KEYWORDS.some((kw) => regLower.includes(kw));
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

  // A brand in the path is weak supporting evidence only. It is deliberately
  // kept separate from hostname impersonation and never creates a strong
  // identity verdict on its own.
  let pathBrand: BrandDefinition | null = null;
  try {
    pathBrand = findBrandByName(decodeURIComponent(pathname));
  } catch {
    pathBrand = findBrandByName(pathname);
  }
  if (pathBrand) {
    return {
      ...base,
      detectedBrand: pathBrand.id,
      relationship: "brand-in-path",
    };
  }

  return base;
}
