import {
  containsBrandKeyword,
  findBrandImpersonation,
  hasExcessiveEncoding,
  hasLookalikePattern,
  isSuspiciousTld,
  isUrlShortener,
} from "@/utils/url";
import type { DetectionRule } from "./ruleEngine";

/**
 * URL-based detection rules (spec §8). Each rule is independent and
 * explainable. No single weak heuristic flags a site as malicious —
 * severity and points are calibrated so only combinations push a score
 * into high-risk bands.
 */
export const urlRules: DetectionRule[] = [
  {
    id: "url-excessive-length",
    name: "Excessive URL length",
    description:
      "Very long URLs are commonly used to hide the real destination from users.",
    severity: "low",
    points: 6,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.urlLength > 120,
      explanation: `URL is ${urlSignals.urlLength} characters long.`,
    }),
  },
  {
    id: "url-ip-host",
    name: "IP address instead of domain",
    description:
      "Legitimate services almost never serve logins or payments directly from a raw IP address.",
    severity: "high",
    points: 18,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.isIpHost,
      explanation: `Host is a raw IP address (${urlSignals.hostname}).`,
    }),
  },
  {
    id: "url-suspicious-tld",
    name: "Suspicious TLD",
    description:
      "This top-level domain is frequently abused in phishing campaigns, though many legitimate sites also use it.",
    severity: "medium",
    points: 10,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: !urlSignals.isIpHost && isSuspiciousTld(urlSignals.tld),
      explanation: `Domain uses the .${urlSignals.tld} TLD.`,
    }),
  },
  {
    id: "url-punycode",
    name: "Punycode domain",
    description:
      "Punycode (xn--) can render lookalike characters that visually imitate trusted domains.",
    severity: "high",
    points: 16,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.hasPunycode,
      explanation: `Hostname contains punycode encoding (${urlSignals.hostname}).`,
    }),
  },
  {
    id: "url-lookalike-domain",
    name: "Lookalike domain pattern",
    description:
      "The domain resembles a well-known brand using character substitutions.",
    severity: "critical",
    points: 24,
    category: "url",
    evaluate: ({ urlSignals }) => {
      const matched = hasLookalikePattern(urlSignals.registrableDomain);
      return {
        matched,
        explanation: matched
          ? `${urlSignals.registrableDomain} mimics a known brand with character substitution.`
          : undefined,
      };
    },
  },
  {
    id: "url-brand-impersonation",
    name: "Brand impersonation pattern",
    description:
      "The hostname mentions a well-known brand but is not that brand's official domain.",
    severity: "high",
    points: 20,
    category: "url",
    evaluate: ({ urlSignals }) => {
      const brand = findBrandImpersonation(
        urlSignals.hostname,
        urlSignals.registrableDomain,
      );
      return {
        matched: brand !== null,
        explanation: brand
          ? `Hostname references "${brand}" but the domain is ${urlSignals.registrableDomain}.`
          : undefined,
      };
    },
  },
  {
    id: "url-nested-subdomains",
    name: "Multiple nested subdomains",
    description:
      "Deeply nested subdomains can disguise the true registrable domain (e.g. login.bank.com.evil.io).",
    severity: "medium",
    points: 10,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.subdomainDepth >= 3,
      explanation: `Hostname has ${urlSignals.subdomainDepth} subdomain levels.`,
    }),
  },
  {
    id: "url-hyphen-overload",
    name: "Excessive hyphens in domain",
    description:
      "Many hyphens are typical of throwaway phishing domains built to read like real ones.",
    severity: "low",
    points: 6,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.hyphenCount >= 3,
      explanation: `Hostname contains ${urlSignals.hyphenCount} hyphens.`,
    }),
  },
  {
    id: "url-encoded-chars",
    name: "URL encoding abuse",
    description: "Heavy percent-encoding can hide the real destination of a link.",
    severity: "medium",
    points: 8,
    category: "url",
    evaluate: ({ url }) => ({
      matched: hasExcessiveEncoding(url),
      explanation: "URL contains heavy percent-encoding.",
    }),
  },
  {
    id: "url-brand-in-path",
    name: "Brand keyword in URL path",
    description:
      "A brand name appears in the path or query of an unrelated domain — common in credential-harvesting links.",
    severity: "low",
    points: 5,
    category: "url",
    evaluate: ({ url, urlSignals }) => ({
      matched:
        !findBrandImpersonation(urlSignals.hostname, urlSignals.registrableDomain) &&
        containsBrandKeyword(`${url}`) &&
        !isUrlShortener(urlSignals.hostname),
      explanation: "URL path/query references a major brand on an unrelated domain.",
    }),
  },
];
