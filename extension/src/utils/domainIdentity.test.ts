import { describe, expect, it } from "vitest";
import {
  BRANDS,
  LOOKALIKE_HIGH_SIMILARITY,
  classifyDomain,
  getRegistrableDomain,
  isOfficialBrandDomain,
  similarity,
} from "./domainIdentity";

/**
 * Spec §4 / §21 rule 8: never flag a legitimate website as impersonation.
 *
 * Regression suite for a real false positive: `youtube.com` is registered as an
 * official domain of the "google" brand, but no google brand NAME appears in
 * the hostname. The official-domain check was gated on the name-matching brand,
 * so it was skipped, and the lookalike loop then compared "youtube" against
 * every official first-label — including "youtube" — scoring 1.0 and flagging
 * YouTube as a "near-exact lookalike domain".
 */

/**
 * The invariant: if a registrable domain is on ANY brand's allowlist, it must
 * never be classified as impersonation. This sweeps the whole registry rather
 * than only the domains that happened to trigger the original bug.
 */
/** Every (brand, official domain) pair in the registry. */
const ALLOWLIST: Array<{ brand: string; domain: string }> = BRANDS.flatMap((brand) =>
  brand.officialDomains.map((domain) => ({ brand: brand.id, domain })),
);

const ALLOWLIST_DOMAINS = ALLOWLIST.map((entry) => entry.domain);

/**
 * The invariant: if a registrable domain is on ANY brand's allowlist, it must
 * never be classified as impersonation. This sweeps the whole registry rather
 * than only the domains that happened to trigger the original bug.
 */
describe("official brand domains are never impersonation (spec §4)", () => {
  it.each(ALLOWLIST)(
    "$brand allowlists $domain without flagging it",
    ({ domain }) => {
      const identity = classifyDomain(domain);

      // The safety property: never impersonation.
      expect(["official", "trusted-subdomain"]).toContain(identity.relationship);
      expect(identity.relationship).not.toBe("lookalike");
      expect(identity.relationship).not.toBe("brand-in-subdomain");

      // A few properties are registered under more than one brand
      // (instagram.com under both `facebook` and `instagram`), so exactly one
      // owner is reported — but it must be a legitimate owner of the domain.
      expect(identity.matchedOfficialDomain).toBe(domain);
      const owners = BRANDS.filter((b) => b.officialDomains.includes(domain)).map(
        (b) => b.id,
      );
      expect(owners).toContain(identity.detectedBrand);
    },
  );

  it("prefers the most specific brand when a domain has several owners", () => {
    // Without this, Instagram would be labelled "Facebook" in the UI.
    expect(classifyDomain("instagram.com").detectedBrand).toBe("instagram");
    expect(classifyDomain("whatsapp.com").detectedBrand).toBe("whatsapp");
    expect(classifyDomain("linkedin.com").detectedBrand).toBe("linkedin");
    expect(classifyDomain("youtube.com").detectedBrand).toBe("google");
  });

  it.each(ALLOWLIST)(
    "www.$domain is a trusted subdomain, not a lookalike",
    ({ domain }) => {
      expect(classifyDomain(`www.${domain}`).relationship).toBe("trusted-subdomain");
    },
  );

  it("does not classify any allowlisted domain as a lookalike at any subdomain depth", () => {
    for (const domain of ALLOWLIST_DOMAINS) {
      for (const host of [domain, `www.${domain}`, `login.${domain}`]) {
        expect(classifyDomain(host).relationship).not.toBe("lookalike");
      }
    }
  });
});

describe("the reported false positive is fixed", () => {
  it("classifies youtube.com as an official google property", () => {
    const identity = classifyDomain("www.youtube.com", "/watch?v=abc");

    expect(identity.registrableDomain).toBe("youtube.com");
    expect(identity.relationship).toBe("trusted-subdomain");
    expect(identity.detectedBrand).toBe("google");
    expect(identity.similarity).toBeUndefined();
  });

  it("reports no lookalike similarity for youtube.com", () => {
    // The bug produced similarity 1.0 against youtube.com itself.
    expect(classifyDomain("www.youtube.com").similarity).toBeUndefined();
  });

  it("still catches a genuine youtube impersonation", () => {
    const identity = classifyDomain("youtube-login-verify.xyz");
    expect(["lookalike", "brand-in-subdomain", "unrelated"]).toContain(
      identity.relationship,
    );
    // It must not be treated as official.
    expect(identity.relationship).not.toBe("official");
    expect(identity.relationship).not.toBe("trusted-subdomain");
  });
});

describe("legitimate brand mentions are not phishing evidence (spec §4)", () => {
  it("does not flag a brand name in the path", () => {
    // Spec §4: example.com/google-tutorial must NOT be flagged merely
    // because "google" appears in the path.
    const identity = classifyDomain("example.com", "/google-tutorial");
    expect(identity.relationship).not.toBe("lookalike");
    expect(identity.relationship).not.toBe("brand-in-subdomain");
  });

  it("does not flag google.com with a brand name in the path", () => {
    expect(
      classifyDomain("www.google.com", "/search?q=paypal").relationship,
    ).toBe("trusted-subdomain");
  });

  it("flags google.com.example.xyz as impersonation", () => {
    const identity = classifyDomain("google.com.example.xyz");
    expect(identity.relationship).not.toBe("official");
    expect(identity.relationship).not.toBe("trusted-subdomain");
  });
});

describe("similarity does not self-match allowlisted labels", () => {
  it("scores an identical label as 1 (this is what caused the bug)", () => {
    // Documents the mechanism: a brand's own domain always scores 1.0, which
    // is why the allowlist check has to run first.
    expect(similarity("youtube", "youtube")).toBe(1);
    expect(similarity("youtube", "youtube")).toBeGreaterThan(
      LOOKALIKE_HIGH_SIMILARITY,
    );
  });

  it("keeps a genuine homoglyph impersonation above the threshold", () => {
    // g00gle must still be caught after the allowlist fix.
    const identity = classifyDomain("g00gle.example");
    expect(identity.relationship).toBe("lookalike");
    expect(identity.similarity).toBeGreaterThan(LOOKALIKE_HIGH_SIMILARITY);
  });
});

describe("registrable domain parsing", () => {
  it("resolves multi-label public suffixes", () => {
    expect(getRegistrableDomain("www.amazon.co.uk")).toBe("amazon.co.uk");
    expect(getRegistrableDomain("shop.google.co.in")).toBe("google.co.in");
  });

  it("isOfficialBrandDomain is an exact match only", () => {
    const google = BRANDS.find((b) => b.id === "google")!;
    expect(isOfficialBrandDomain("youtube.com", google)).toBe(true);
    expect(isOfficialBrandDomain("youtube.com.evil.xyz", google)).toBe(false);
  });
});