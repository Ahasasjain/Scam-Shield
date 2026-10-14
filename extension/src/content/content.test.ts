import { describe, expect, it } from "vitest";
import { containsSensitiveFormFields, kindsIn } from "./index";

/**
 * Spec §3 / §7 / §22 coverage for before-submit protection.
 *
 * Two tiers are asserted here on purpose:
 * - HIGH IMPACT (password, OTP, card, CVV, UPI, banking) interrupts a submit.
 * - Personal data (phone, DOB, government ID) is detected and reported but
 *   must NOT interrupt, because almost every legitimate site asks for it.
 *   Conflating the two would be a mass false-positive source.
 */

function formWith(html: string): HTMLFormElement {
  const form = document.createElement("form");
  form.innerHTML = html;
  return form;
}

describe("high-impact sensitive form detection", () => {
  it.each([
    ['<input type="password">', "password"],
    ['<input autocomplete="cc-number">', "card"],
    ['<input name="otp">', "otp"],
    ['<input name="upi_id">', "upi"],
    ['<input name="cvv">', "cvv"],
  ])("detects %s without reading its value", (input, kind) => {
    const form = formWith(input);
    const field = form.querySelector("input");
    field?.setAttribute("value", "secret-value");
    expect(containsSensitiveFormFields(form)).toBe(true);
    expect(kindsIn(form)).toContain(kind);
  });

  it("does not flag a non-sensitive form", () => {
    const form = formWith('<input type="text" name="search">');
    expect(containsSensitiveFormFields(form)).toBe(false);
  });

  it("never reads the field's value", () => {
    // The detectors must be structural. A password value must not appear
    // anywhere in the reported signal set.
    const form = formWith('<input type="password" name="pw">');
    form.querySelector("input")?.setAttribute("value", "hunter2");
    expect(JSON.stringify(kindsIn(form))).not.toContain("hunter2");
  });
});

describe("banking fields are reported but not blocking", () => {
  // Regression: amazon.in/ap/signin was flagged "Banking credentials
  // requested" (high severity, 24 pts) and could be blocked. Banking-style
  // fields appear on legitimate bank logins and retailer billing pages, and
  // the selectors match attribute substrings. Real banking phishing is caught
  // by correlation (unknown domain + credentials), not by blocking.
  it.each([
    '<input name="accountNumber">',
    '<input name="routingNumber">',
    '<input name="iban">',
    '<input name="netBankingId">',
    '<input name="pin" type="password">',
  ])("detects %s as a banking field", (input) => {
    const form = formWith(input);
    expect(kindsIn(form)).toContain("banking");
  });

  it("does not interrupt submission for a banking-only form", () => {
    expect(containsSensitiveFormFields(formWith('<input name="accountNumber">'))).toBe(
      false,
    );
  });

  it("still interrupts when a banking field sits beside a password field", () => {
    const form = formWith(
      '<input name="accountNumber"><input type="password" name="pw">',
    );
    expect(containsSensitiveFormFields(form)).toBe(true);
  });
});

describe("personal data is reported but not blocking", () => {
  it.each([
    '<input type="tel" name="mobile">',
    '<input name="dateOfBirth">',
    '<input name="date of birth">',
    '<input name="dob">',
    '<input name="phone">',
    '<input name="aadhaar">',
    '<input name="passportNumber">',
  ])("detects %s as personal data", (input) => {
    const form = formWith(input);
    expect(kindsIn(form)).toContain("personal");
  });

  it("does not interrupt submission for a phone-only form", () => {
    // A newsletter/checkout phone field must not trip the guard, otherwise
    // the warning becomes noise on ordinary e-commerce sites.
    const form = formWith('<input type="tel" name="mobile">');
    expect(containsSensitiveFormFields(form)).toBe(false);
  });

  it("does not interrupt submission for an ID-only form", () => {
    const form = formWith('<input name="aadhaar">');
    expect(containsSensitiveFormFields(form)).toBe(false);
  });

  it("still interrupts when a phone field sits beside a password field", () => {
    const form = formWith(
      '<input type="tel" name="mobile"><input type="password" name="pw">',
    );
    expect(containsSensitiveFormFields(form)).toBe(true);
  });
});
