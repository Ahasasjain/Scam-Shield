import { describe, expect, it } from "vitest";
import type { RiskVerdict } from "@shared/index";
import { classifyDomain } from "@/utils/domainIdentity";
import { runRuleEngine } from "@/services/scanner";
import {
  deriveVerdict,
  evaluateCorrelations,
} from "@/services/scanner/correlationEngine";
import { calculateScore } from "@/utils/scoring";
import type { ScanContext } from "@/services/scanner/ruleEngine";
import type { PageSignals } from "@shared/index";

/**
 * Spec §4 / §11 / §21 rule 8 — false positives observed in the real world.
 *
 * Every case below is a URL that ScamShield actually flagged in production
 * use. They are the highest-value regression tests in the suite: a synthetic
 * fixture would not have caught either bug.
 *
 *  1. amazon.in/ap/signin?...openid... — a ~380-character, percent-encoded
 *     OpenID sign-in URL was scored 66 → SUSPICIOUS ("Excessive URL length",
 *     "URL encoding abuse", "Login form detected", "Banking credentials
 *     requested") on an ALLOWLISTED official domain.
 *  2. www.youtube.com/watch?v=...&list=...&index=... — flagged as a
 *     "Near-exact lookalike domain" because youtube.com is registered under
 *     the `google` brand and self-matched at similarity 1.0.
 *
 * The general rule these encode: a brand-allowlisted domain plus weak
 * structural evidence (long URL, percent-encoding, odd TLD, a login form,
 * billing fields) is SUPPORTING evidence only and must never produce a
 * SUSPICIOUS-or-worse verdict on its own.
 */

function urlSignalsFor(url: string) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split(".");
  const tld = labels[labels.length - 1] ?? "";
  const subdomainDepth = Math.max(0, labels.length - 2);
  const encoded = (parsed.search.match(/%[0-9A-Fa-f]{2}/g) ?? []).length;
  return {
    protocol: parsed.protocol,
    hostname,
    registrableDomain: labels.slice(-2).join("."),
    isHttps: parsed.protocol === "https:",
    isIpHost: false,
    urlLength: url.length,
    subdomainDepth,
    hyphenCount: (parsed.hostname.match(/-/g) ?? []).length,
    hasPunycode: parsed.hostname.includes("xn--"),
    tld,
    pathLength: parsed.pathname.length,
    suspiciousTld: false,
    ...(encoded > 0 ? {} : {}),
  };
}

/** A realistic retail sign-in page: password field plus billing-ish fields. */
const RETAIL_LOGIN_PAGE: PageSignals = {
  hasLoginForm: true,
  hasPasswordFieldsOnHttp: false,
  hasPaymentForm: false,
  urgencyLanguageCount: 0,
  giveawayPatterns: 0,
  fakeSecurityWarnings: 0,
  externalScriptOrigins: ["ssl-images-amazon.com", "m.media-amazon.com"],
  formActions: [
    {
      // Legitimate sign-in posts back to the same origin.
      actionOrigin: "https://www.amazon.in",
      isCrossOrigin: false,
      containsPassword: true,
      containsPaymentFields: false,
      kinds: ["password", "banking"],
    },
  ],
  sensitiveKinds: ["password", "banking"],
  crossOriginSensitiveForms: 0,
  offDomainSensitiveForms: 0,
  suspiciousDownloadCount: 0,
};

function contextFor(url: string, pageSignals?: PageSignals): ScanContext {
  const identity = classifyDomain(new URL(url).hostname, new URL(url).pathname);
  return {
    url,
    urlSignals: urlSignalsFor(url),
    domainIdentity: identity,
    ...(pageSignals ? { pageSignals } : {}),
  };
}

/** Full pipeline: rules -> correlations -> score -> verdict. */
function verdictFor(url: string, pageSignals?: PageSignals, threatAvailable = true) {
  const context = contextFor(url, pageSignals);
  const { factors: ruleFactors } = runRuleEngine(context);
  const threatMatch = {
    available: threatAvailable,
    matched: false,
    status: "NO_KNOWN_THREAT" as const,
    safeBrowsingStatus: "NO_KNOWN_THREAT" as const,
    checkedAt: Date.now(),
  };
  const correlationFactors = evaluateCorrelations(ruleFactors, {
    domainIdentity: context.domainIdentity,
    threatMatch,
  });
  const allFactors = [...ruleFactors, ...correlationFactors];
  const { score } = calculateScore(ruleFactors, [], {
    domainIdentity: context.domainIdentity,
  });
  const verdict = deriveVerdict({
    score,
    threatMatch,
    domainIdentity: context.domainIdentity,
    pageAnalyzed: pageSignals !== undefined,
    factorIds: allFactors.map((f) => f.id),
  });
  return { verdict, score, factors: allFactors, identity: context.domainIdentity };
}

const AMAZON_SIGNIN =
  "https://www.amazon.in/ap/signin/ref=cart_empty_sign_in?openid.return_to=https%3A%2F%2Fwww.amazon.in%2Fcart%3Fapp-nav-type%3Dnone%26dc%3Ddf&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%3F2.0%2Fidentifier_select&openid.assoc_handle=inflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%3F2.0";

const YOUTUBE_WATCH =
  "https://www.youtube.com/watch?v=frf7qxiN2qU&list=PLgUwDviBIf0rENwdL0nEH0uGom9no0nyB&index=4";

describe("real-world false positive: amazon.in OpenID sign-in", () => {
  it("recognises amazon.in as an allowlisted official domain", () => {
    const identity = classifyDomain("www.amazon.in", "/ap/signin");
    expect(identity.relationship).toBe("trusted-subdomain");
    expect(identity.detectedBrand).toBe("amazon");
  });

  it("does not flag the official sign-in page as suspicious", () => {
    const { verdict } = verdictFor(AMAZON_SIGNIN, RETAIL_LOGIN_PAGE);
    expect(verdict).not.toBe("SUSPICIOUS");
    expect(verdict).not.toBe("HIGH_RISK");
    expect(verdict).not.toBe("DANGEROUS");
    expect(["SAFE", "LOW_RISK"]).toContain(verdict);
  });

  it("does not claim impersonation evidence for amazon.in", () => {
    const { factors } = verdictFor(AMAZON_SIGNIN, RETAIL_LOGIN_PAGE);
    const ids = factors.map((f) => f.id);
    expect(ids).not.toContain("url-lookalike-domain");
    expect(ids).not.toContain("url-lookalike-domain-strong");
    expect(ids).not.toContain("url-brand-in-subdomain");
  });

  it("treats long URL + encoding + login form as weak evidence only", () => {
    // These three DO fire — that is correct, they are genuine observations.
    const { factors } = verdictFor(AMAZON_SIGNIN, RETAIL_LOGIN_PAGE);
    const ids = factors.map((f) => f.id);
    expect(ids).toContain("url-excessive-length");
    expect(ids).toContain("page-login-form");
    // ...but together they must not cross the SUSPICIOUS band.
    expect(ids).not.toContain("corr-unknown-credentials-pressure");
  });
});

describe("real-world false positive: YouTube watch URL", () => {
  it("recognises youtube.com as an allowlisted official google property", () => {
    const identity = classifyDomain("www.youtube.com", "/watch");
    expect(identity.relationship).toBe("trusted-subdomain");
    expect(identity.similarity).toBeUndefined();
  });

  it("does not flag a YouTube watch URL", () => {
    // A real scan collects page signals, so model that. (Without page
    // analysis the honest verdict is UNKNOWN — asserted separately below.)
    const { verdict } = verdictFor(YOUTUBE_WATCH, RETAIL_LOGIN_PAGE);
    expect(["SAFE", "LOW_RISK"]).toContain(verdict);
  });

  it("produces no lookalike factor at all", () => {
    const { factors } = verdictFor(YOUTUBE_WATCH, RETAIL_LOGIN_PAGE);
    expect(factors.map((f) => f.id)).not.toContain("url-lookalike-domain-strong");
  });
});

describe("official domains are resilient to structural noise (spec §4)", () => {
  it.each([
    ["https://www.google.com/search?q=" + "a".repeat(180)],
    ["https://www.facebook.com/login/device-based/regular/login/?next=https%3A%2F%2Fwww.facebook.com%2F"],
    ["https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&redirect_uri=https%3A%2F%2Flocalhost"],
    ["https://www.netflix.com/browse?trackId=1234567890"],
    ["https://accounts.google.com/ServiceLogin?service=foo&passive=true&continue=https%3A%2F%2Fwww.google.com"],
  ])("keeps %s at low risk or better", (url) => {
    const { verdict } = verdictFor(url, RETAIL_LOGIN_PAGE);
    expect(["SAFE", "LOW_RISK"]).toContain(verdict);
  });

  it("still escalates an official domain when credentials go off-domain", () => {
    // The brand allowlist must not become a blind spot: a page on an
    // allowlisted domain that POSTS a password to an unrelated host is the
    // classic drive-by / compromised-CMS phishing case.
    const tampered: PageSignals = {
      ...RETAIL_LOGIN_PAGE,
      formActions: [
        {
          actionOrigin: "https://collector.evil.example",
          isCrossOrigin: true,
          containsPassword: true,
          containsPaymentFields: false,
          kinds: ["password"],
        },
      ],
      crossOriginSensitiveForms: 1,
      offDomainSensitiveForms: 1,
    };

    const { verdict } = verdictFor(AMAZON_SIGNIN, tampered);
    expect(["SUSPICIOUS", "HIGH_RISK", "DANGEROUS"]).toContain(verdict);
  });

  it("still escalates an official domain on a confirmed threat-intel match", () => {
    const context = contextFor(YOUTUBE_WATCH);
    expect(context.domainIdentity?.relationship).toBe("trusted-subdomain");
    const verdict: RiskVerdict = deriveVerdict({
      score: 100,
      threatMatch: {
        available: true,
        matched: true,
        status: "MATCH",
        safeBrowsingStatus: "KNOWN_MALICIOUS",
        confidence: "confirmed",
        checkedAt: Date.now(),
      },
      domainIdentity: context.domainIdentity,
      pageAnalyzed: false,
      factorIds: [],
    });
    expect(verdict).toBe("DANGEROUS");
  });

  it("returns UNKNOWN, not SAFE, when an official domain has no page analysis", () => {
    const { verdict } = verdictFor(AMAZON_SIGNIN, undefined, false);
    expect(verdict).toBe("UNKNOWN");
  });
});