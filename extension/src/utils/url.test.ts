import { describe, expect, it } from "vitest";
import {
  containsBrandKeyword,
  findBrandImpersonation,
  hasExcessiveEncoding,
  hasLookalikePattern,
  isChromeInternalUrl,
  isSuspiciousTld,
  isUrlShortener,
  parseUrl,
} from "@/utils/url";

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

  it("detects brand impersonation on non-official domains", () => {
    const brand = findBrandImpersonation("paypal.secure-login.evil.xyz", "evil.xyz");
    expect(brand).toBe("paypal");
  });

  it("does not flag the official brand domain", () => {
    expect(findBrandImpersonation("www.paypal.com", "paypal.com")).toBeNull();
  });

  it("detects lookalike homoglyph patterns", () => {
    expect(hasLookalikePattern("paypa1.com")).toBe(true);
    expect(hasLookalikePattern("example.com")).toBe(false);
  });

  it("identifies chrome internal URLs", () => {
    expect(isChromeInternalUrl("chrome://version")).toBe(true);
    expect(isChromeInternalUrl("https://example.com")).toBe(false);
  });
});
