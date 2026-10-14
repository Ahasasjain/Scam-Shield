/**
 * URL parsing and classification helpers used by the rule engine.
 * Pure functions — no Chrome APIs — so they are trivially testable.
 *
 * Brand/impersonation logic has moved to `domainIdentity.ts`, which uses
 * the Public Suffix List and a brand registry. This module keeps only
 * structural URL parsing.
 */

import { getRegistrableDomain } from "@/utils/domainIdentity";

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

/** Well-known brand keywords — used only for path-based weak signals now. */
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
  suspiciousTld: boolean;
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
  // IPv4 literals match the dotted-quad pattern; IPv6 literals (brackets are
  // already stripped by URL.hostname) contain colons. Both evade domain
  // reputation and must hit the url-ip-host rule instead of being parsed as
  // ordinary domains.
  const isIpHost = IPV4_PATTERN.test(hostname) || hostname.includes(":");
  const parts = hostname.split(".");
  const tld = parts.length > 1 ? (parts.at(-1) ?? "") : "";
  const registrableDomain = getRegistrableDomain(hostname) ?? hostname;

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
    suspiciousTld: isSuspiciousTld(tld),
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

export function isChromeInternalUrl(url: string): boolean {
  return /^(chrome|edge|about|chrome-extension|devtools|view-source):/i.test(url);
}
