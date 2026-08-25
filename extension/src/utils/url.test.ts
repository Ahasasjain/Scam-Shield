import { describe, expect, it } from "vitest";
import {
  containsBrandKeyword,
  hasExcessiveEncoding,
  isChromeInternalUrl,
  isSuspiciousTld,
  isUrlShortener,
  parseUrl,
} from "@/utils/url";
import {
  classifyDomain,
  getRegistrableDomain,
  normalizeDomainLabel,
  similarity,
} from "@/utils/domainIdentity";

describe("parseUrl", () => {
  it("parses a normal https URL", () => {
    const result = parseUrl("https://www.example.com/path");
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.hostname).toBe("www.example.com");
      expect(result.isHttps).toBe(true);
      expect(result.subdomainDepth).toBe(1);
    }
  });

  it("rejects malformed URLs", () => {
    expect(parseUrl("not a url").valid).toBe(false);
  });

  it("rejects non-http protocols", () => {
    expect(parseUrl("ftp://files.example.com").valid).toBe(false);
  });

  it("detects IP hosts", () => {
    const result = parseUrl("http://192.168.1.1/login");
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.isIpHost).toBe(true);
  });

  it("detects punycode domains", () => {
    const result = parseUrl("https://xn--pple-43d.com");
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.hasPunycode).toBe(true);
  });

  it("counts hyphens in hostname", () => {
    const result = parseUrl("https://secure-login-verify-account.com");
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.hyphenCount).toBeGreaterThanOrEqual(3);
  });
});

describe("heuristics", () => {
  it("flags suspicious TLDs", () => {
    expect(isSuspiciousTld("xyz")).toBe(true);
    expect(isSuspiciousTld("com")).toBe(false);
  });

  it("recognizes URL shorteners", () => {
    expect(isUrlShortener("bit.ly")).toBe(true);
    expect(isUrlShortener("example.com")).toBe(false);
  });

  it("detects excessive encoding", () => {
    expect(hasExcessiveEncoding("https://a.com/%41%42%43%44%45%46")).toBe(true);
    expect(hasExcessiveEncoding("https://a.com/hello%20world")).toBe(false);
  });

  it("detects brand keywords", () => {
    expect(containsBrandKeyword("https://login-paypal-secure.xyz")).toBe(true);
    expect(containsBrandKeyword("https://example.com")).toBe(false);
  });

  it("identifies chrome internal URLs", () => {
    expect(isChromeInternalUrl("chrome://version")).toBe(true);
    expect(isChromeInternalUrl("https://example.com")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Public Suffix List parsing (§1.2)
// ---------------------------------------------------------------------------

describe("PSL registrable-domain parsing", () => {
  it("handles simple domains", () => {
    expect(getRegistrableDomain("accounts.google.com")).toBe("google.com");
  });

  it("handles multi-part public suffixes (co.uk)", () => {
    expect(getRegistrableDomain("foo.example.co.uk")).toBe("example.co.uk");
  });

  it("handles github.io style suffixes", () => {
    expect(getRegistrableDomain("foo.bar.github.io")).toBe("bar.github.io");
  });
});

// ---------------------------------------------------------------------------
// Similarity function (§7)
// ---------------------------------------------------------------------------

describe("similarity", () => {
  it("returns 1 for identical strings", () => {
    expect(similarity("paypal", "paypal")).toBe(1);
  });

  it("returns high similarity for homoglyph lookalikes", () => {
    // Production normalizes before comparing — mirror that here.
    expect(similarity(normalizeDomainLabel("paypa1"), normalizeDomainLabel("paypal"))).toBe(1);
    expect(similarity(normalizeDomainLabel("g00gle"), normalizeDomainLabel("google"))).toBe(1);
  });

  it("returns low similarity for unrelated strings", () => {
    expect(similarity("example", "paypal")).toBeLessThan(0.5);
  });
});

// ---------------------------------------------------------------------------
// Domain relationship classifier — the Google/Facebook regression suite (§24)
// ---------------------------------------------------------------------------

describe("classifyDomain — official domains must NOT be flagged", () => {
  const officialHostnames = [
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "developers.google.com",
    "mail.google.com",
    "facebook.com",
    "www.facebook.com",
    "m.facebook.com",
    "paypal.com",
    "www.paypal.com",
  ];

  for (const hostname of officialHostnames) {
    it(`${hostname} → no impersonation/lookalike`, () => {
      const identity = classifyDomain(hostname);
      expect(
        identity.relationship === "official" ||
          identity.relationship === "trusted-subdomain",
      ).toBe(true);
    });
  }
});

describe("classifyDomain — attacker patterns MUST be flagged", () => {
  it("brand in attacker subdomain", () => {
    const identity = classifyDomain("google.login.attacker.example");
    expect(identity.relationship).toBe("brand-in-subdomain");
  });

  it("facebook brand in attacker subdomain", () => {
    const identity = classifyDomain("facebook.verify.attacker.example");
    expect(identity.relationship).toBe("brand-in-subdomain");
  });

  it("homoglyph lookalike domain", () => {
    const identity = classifyDomain("paypa1.example");
    expect(identity.relationship).toBe("lookalike");
    expect(identity.similarity ?? 0).toBeGreaterThanOrEqual(0.7);
  });

  it("g00gle-style lookalike", () => {
    const identity = classifyDomain("g00gle.example");
    expect(identity.relationship).toBe("lookalike");
  });

  it("unrelated domain with no brand stays unrelated", () => {
    const identity = classifyDomain("myportfolio.example.xyz");
    expect(identity.relationship).toBe("unrelated");
  });
});
