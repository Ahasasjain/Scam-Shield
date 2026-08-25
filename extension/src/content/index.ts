/**
 * ScamShield content script — injected ON DEMAND via chrome.scripting
 * (spec §31: no unnecessary content scripts running on every page).
 *
 * Collects ONLY aggregate page signals (spec §12, §26):
 * - presence of login/payment forms (never field values)
 * - counts of urgency/giveaway/fake-warning phrases
 * - origins of external scripts (hostnames only)
 *
 * It never reads input values, cookies, tokens, or full page text.
 */

export interface CollectedPageSignals {
  hasLoginForm: boolean;
  hasPasswordFieldsOnHttp: boolean;
  hasPaymentForm: boolean;
  urgencyLanguageCount: number;
  giveawayPatterns: number;
  fakeSecurityWarnings: number;
  externalScriptOrigins: string[];
}

const URGENCY_PATTERNS = [
  /act\s+now/i,
  /limited\s+time/i,
  /account\s+(will\s+be\s+)?suspended/i,
  /verify\s+your\s+account\s+immediately/i,
  /urgent/i,
  /immediate\s+action\s+required/i,
  /your\s+account\s+has\s+been\s+(locked|compromised)/i,
  /expires?\s+today/i,
];

const GIVEAWAY_PATTERNS = [
  /you\s+(have\s+)?won/i,
  /congratulations[!,]?\s+you/i,
  /claim\s+your\s+(prize|reward)/i,
  /free\s+(iphone|gift\s+card|money)/i,
  /lottery\s+winner/i,
  /\$\d+(,\d{3})*\s+(prize|reward|cash)/i,
];

const FAKE_WARNING_PATTERNS = [
  /your\s+computer\s+has\s+(a\s+)?virus/i,
  /system\s+scan\s+detected/i,
  /(browser|chrome)\s+has\s+been\s+blocked/i,
  /critical\s+(error|alert)\s*[:!]/i,
  /call\s+(support|tech( nical)? support)\s+now/i,
  /windows\s+defender\s*[:]\s*(threat|virus)/i,
];

const PAYMENT_HINTS = [
  'input[autocomplete="cc-number"]',
  'input[name*="card" i]',
  'input[id*="card" i]',
  'input[placeholder*="card number" i]',
];

function countMatches(text: string, patterns: RegExp[]): number {
  return patterns.reduce(
    (count, pattern) => (pattern.test(text) ? count + 1 : count),
    0,
  );
}

function collectSignals(): CollectedPageSignals {
  const isHttps = globalThis.location.protocol === "https:";

  const passwordFields = document.querySelectorAll('input[type="password"]');
  const hasLoginForm = passwordFields.length > 0;

  let hasPaymentForm = false;
  for (const selector of PAYMENT_HINTS) {
    if (document.querySelector(selector) !== null) {
      hasPaymentForm = true;
      break;
    }
  }

  // Visible text scan — bounded to avoid expensive traversal on huge pages.
  const bodyText = (document.body?.innerText ?? "").slice(0, 50_000);

  const externalScriptOrigins = Array.from(
    new Set(
      Array.from(document.querySelectorAll("script[src]"))
        .map((s) => (s as HTMLScriptElement).src)
        .filter((src) => {
          try {
            return new URL(src).origin !== globalThis.location.origin;
          } catch {
            return false;
          }
        })
        .map((src) => new URL(src).hostname),
    ),
  ).slice(0, 50);

  return {
    hasLoginForm,
    hasPasswordFieldsOnHttp: !isHttps && hasLoginForm,
    hasPaymentForm,
    urgencyLanguageCount: countMatches(bodyText, URGENCY_PATTERNS),
    giveawayPatterns: countMatches(bodyText, GIVEAWAY_PATTERNS),
    fakeSecurityWarnings: countMatches(bodyText, FAKE_WARNING_PATTERNS),
    externalScriptOrigins,
  };
}

// Injected once per scan by the background worker; this script then answers
// signal-collection requests over the extension messaging channel.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: string }).type === "COLLECT_PAGE_SIGNALS"
  ) {
    try {
      sendResponse({ ok: true, signals: collectSignals() });
    } catch {
      sendResponse({ ok: false, reason: "Signal collection failed" });
    }
  }
  // Return true only when responding asynchronously — here it's synchronous.
  return false;
});
