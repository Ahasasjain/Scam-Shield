/**
 * URL parsing and classification helpers used by the rule engine.
 * Pure functions — no Chrome APIs — so they are trivially testable.
 */

const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "top",
  "xyz",
  "club",
  "loan",
  "work",
  "click",
  "link",
  "fit",
  "rest",
  "cam",
  "quest",
  "cfd",
  "sbs",
]);

const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rb.gy",
]);

/** Well-known brand keywords used in impersonation heuristics. */
const BRAND_KEYWORDS = [
  "paypal",
  "google",
  "facebook",
  "microsoft",
  "apple",
  "amazon",
  "netflix",
  "instagram",
  "whatsapp",
  "linkedin",
  "wellsfargo",
  "chase",
  "hsbc",
  "sbi",
  "hdfcbank",
  "icicibank",
  "axisbank",
  "coinbase",
  "binance",
  "steamcommunity",
];

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export interface ParsedUrlInfo {
  valid: true;
  href: string;
  protocol: string;
  hostname: string;
  registrableDomain: string;
  isHttps: boolean;
  isIpHost: boolean;
  urlLength: number;
  subdomainDepth: number;
  hyphenCount: number;
  hasPunycode: boolean;
  tld: string;
  pathLength: number;
}

export type ParsedUrl = ParsedUrlInfo | { valid: false; reason: string };

export function parseUrl(rawUrl: string): ParsedUrl {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { valid: false, reason: "Malformed URL" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { valid: false, reason: `Unsupported protocol: ${url.protocol}` };
  }

  const hostname = url.hostname.toLowerCase();
  const isIpHost = IPV4_PATTERN.test(hostname);
  const parts = hostname.split(".");
  const tld = parts.length > 1 ? (parts.at(-1) ?? "") : "";
  // Approximate registrable domain: last two labels (does not cover multi-part
  // public suffixes like co.uk — acceptable heuristic for V1).
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;

  return {
    valid: true,
    href: url.href,
    protocol: url.protocol.replace(":", ""),
    hostname,
    registrableDomain,
    isHttps: url.protocol === "https:",
    isIpHost,
    urlLength: url.href.length,
    subdomainDepth: Math.max(0, parts.length - 2),
    hyphenCount: (hostname.match(/-/g) ?? []).length,
    hasPunycode: hostname.includes("xn--"),
    tld,
    pathLength: url.pathname.length,
  };
}

export function isSuspiciousTld(tld: string): boolean {
  return SUSPICIOUS_TLDS.has(tld.toLowerCase());
}

export function isUrlShortener(hostname: string): boolean {
  return URL_SHORTENERS.has(hostname.toLowerCase());
}

export function hasExcessiveEncoding(url: string): boolean {
  const encoded = url.match(/%[0-9a-fA-F]{2}/g);
  return (encoded?.length ?? 0) >= 5;
}

export function containsBrandKeyword(text: string): boolean {
  const lower = text.toLowerCase();
  return BRAND_KEYWORDS.some((brand) => lower.includes(brand));
}

/**
 * Returns the brand keyword if the URL's hostname contains a brand name but
 * the registrable domain is NOT the brand's official domain — the classic
 * impersonation pattern (e.g. paypal-secure-login.example.com).
 */
export function findBrandImpersonation(
  hostname: string,
  registrableDomain: string,
): string | null {
  const lower = hostname.toLowerCase();
  const domain = registrableDomain.toLowerCase();
  for (const brand of BRAND_KEYWORDS) {
    if (lower.includes(brand) && domain !== `${brand}.com`) {
      return brand;
    }
  }
  return null;
}

/** Common homoglyph substitutions used in lookalike domains. */
const HOMOGLYPHS: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "8": "b",
  vv: "w",
  rn: "m",
};

export function hasLookalikePattern(registrableDomain: string): boolean {
  const name = registrableDomain.split(".")[0] ?? "";
  if (name.length < 4) return false;
  const normalized = Object.entries(HOMOGLYPHS).reduce(
    (acc, [from, to]) => acc.replaceAll(from, to),
    name,
  );
  return BRAND_KEYWORDS.some(
    (brand) => normalized === brand || normalized === `${brand}secure`,
  );
}

export function isChromeInternalUrl(url: string): boolean {
  return /^(chrome|edge|about|chrome-extension|devtools|view-source):/i.test(url);
}
