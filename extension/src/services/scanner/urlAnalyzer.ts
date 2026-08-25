import type { DetectionRule } from "./ruleEngine";
import {
  LOOKALIKE_HIGH_SIMILARITY,
  LOOKALIKE_MODERATE_SIMILARITY,
  type DomainIdentity,
} from "@/utils/domainIdentity";

/**
 * URL-based detection rules, rewritten per docs/scamshield-rule-engine-changes.md.
 *
 * Design principles:
 * - Brand/impersonation findings come from the DomainIdentity classifier,
 *   never from "hostname contains brand string".
 * - Weak structural signals are supporting evidence only (§9) — small points.
 * - Official/trusted domains suppress ONLY brand-impersonation rules (§5);
 *   they do not suppress HTTPS/page/redirect findings.
 */

function identityOf(context: { domainIdentity?: DomainIdentity }): DomainIdentity | null {
  return context.domainIdentity ?? null;
}

export const urlRules: DetectionRule[] = [
  // ------------------------------------------------------------------
  // §9 — weak structural evidence. Small points; never decisive alone.
  // ------------------------------------------------------------------
  {
    id: "url-excessive-length",
    name: "Excessive URL length",
    description:
      "Very long URLs can hide the real destination. Weak signal on its own.",
    severity: "low",
    points: 2,
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
    name: "Uncommon TLD frequently abused",
    description:
      "This top-level domain appears in phishing campaigns more often than average. Weak signal alone — meaningful mainly in combination with other indicators.",
    severity: "low",
    points: 3,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: !urlSignals.isIpHost && urlSignals.suspiciousTld === true,
      explanation: `Domain uses the .${urlSignals.tld} TLD.`,
    }),
  },
  {
    id: "url-punycode",
    name: "Punycode domain",
    description:
      "Punycode (xn--) can render lookalike characters that visually imitate trusted domains.",
    severity: "medium",
    points: 12,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.hasPunycode,
      explanation: `Hostname contains punycode encoding (${urlSignals.hostname}).`,
    }),
  },
  {
    id: "url-nested-subdomains",
    name: "Multiple nested subdomains",
    description:
      "Deeply nested subdomains can disguise the true registrable domain. Only meaningful when combined with brand keywords on unrelated domains.",
    severity: "low",
    points: 3,
    category: "url",
    evaluate: ({ urlSignals, domainIdentity }) => ({
      matched:
        urlSignals.subdomainDepth >= 3 &&
        domainIdentity?.relationship !== "official" &&
        domainIdentity?.relationship !== "trusted-subdomain",
      explanation: `Hostname has ${urlSignals.subdomainDepth} subdomain levels.`,
    }),
  },
  {
    id: "url-hyphen-overload",
    name: "Excessive hyphens in domain",
    description:
      "Many hyphens are typical of throwaway phishing domains built to read like real ones.",
    severity: "low",
    points: 2,
    category: "url",
    evaluate: ({ urlSignals }) => ({
      matched: urlSignals.hyphenCount >= 3,
      explanation: `Hostname contains ${urlSignals.hyphenCount} hyphens.`,
    }),
  },
  {
    id: "url-encoded-chars",
    name: "URL encoding abuse",
    description:
      "Heavy percent-encoding can hide the real destination of a link.",
    severity: "low",
    points: 3,
    category: "url",
    evaluate: ({ url }) => ({
      matched: hasHeavyEncoding(url),
      explanation: "URL contains heavy percent-encoding.",
    }),
  },

  // ------------------------------------------------------------------
  // §6 — brand impersonation via the classifier. Strong evidence.
  // ------------------------------------------------------------------
  {
    id: "url-brand-in-subdomain",
    name: "Brand name in unrelated subdomain",
    description:
      "The hostname places a well-known brand in a subdomain of an unrelated registrable domain — the classic 'google.login.attacker.example' pattern used to trick users into trusting the page.",
    severity: "high",
    points: 22,
    category: "url",
    evaluate: (ctx) => {
      const id = identityOf(ctx);
      const matched = id?.relationship === "brand-in-subdomain";
      return {
        matched,
        explanation: matched
          ? `"${id?.detectedBrand}" appears in the subdomain of an unrelated domain (${id?.registrableDomain}).`
          : undefined,
      };
    },
  },
  {
    id: "url-lookalike-domain",
    name: "Lookalike domain",
    description:
      "The registrable domain closely resembles a well-known brand's official domain after character-substitution normalization.",
    severity: "high",
    points: 24,
    category: "url",
    evaluate: (ctx) => {
      const id = identityOf(ctx);
      const matched =
        id?.relationship === "lookalike" &&
        (id.similarity ?? 0) >= LOOKALIKE_MODERATE_SIMILARITY;
      return {
        matched,
        explanation: matched
          ? `${id?.registrableDomain} resembles ${id?.matchedOfficialDomain} (similarity ${(100 * (id?.similarity ?? 0)).toFixed(0)}%).`
          : undefined,
      };
    },
  },
  {
    id: "url-lookalike-domain-strong",
    name: "Near-exact lookalike domain",
    description:
      "The registrable domain is nearly identical to a well-known brand's official domain — very strong impersonation evidence.",
    severity: "critical",
    points: 30,
    category: "url",
    evaluate: (ctx) => {
      const id = identityOf(ctx);
      const matched =
        id?.relationship === "lookalike" &&
        (id.similarity ?? 0) >= LOOKALIKE_HIGH_SIMILARITY;
      return {
        matched,
        explanation: matched
          ? `${id?.registrableDomain} is near-identical to ${id?.matchedOfficialDomain} (${(100 * (id?.similarity ?? 0)).toFixed(0)}% similar).`
          : undefined,
      };
    },
  },

  // ------------------------------------------------------------------
  // §8 — brand-in-path demoted to weak supporting evidence.
  // ------------------------------------------------------------------
  {
    id: "url-brand-in-path",
    name: "Brand keyword in URL path",
    description:
      "A brand name appears in the path of an unrelated domain. Common and usually harmless — meaningful only alongside other indicators.",
    severity: "low",
    points: 2,
    category: "url",
    evaluate: (ctx) => {
      const id = identityOf(ctx);
      if (!id || id.detectedBrand === undefined) {
        return { matched: false };
      }
      const weaker =
        id.relationship !== "official" &&
        id.relationship !== "trusted-subdomain" &&
        id.relationship !== "brand-in-subdomain" &&
        id.relationship !== "lookalike";
      return {
        matched: weaker && ctx.url.length > 40,
        explanation: weaker
          ? `Path references "${id.detectedBrand}" on an unrelated domain.`
          : undefined,
      };
    },
  },
];

/** ≥5 percent-encoded sequences — kept here so url.ts stays parsing-only. */
function hasHeavyEncoding(url: string): boolean {
  return (url.match(/%[0-9a-fA-F]{2}/g)?.length ?? 0) >= 5;
}
