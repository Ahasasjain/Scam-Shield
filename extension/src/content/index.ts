/**
 * ScamShield content script — injected ON DEMAND via chrome.scripting
 * (spec §31: no unnecessary content scripts running on every page).
 *
 * Collects ONLY aggregate structural metadata (spec §3, §16):
 * - which CATEGORIES of sensitive field exist (never their values)
 * - where credential/payment forms submit (origins only)
 * - counts of urgency / giveaway / fake-warning phrases
 *
 * It NEVER reads input values, cookies, tokens, or full page text beyond a
 * bounded pattern scan of already-rendered text.
 *
 * PHASE 3 (§3): dangerous-action detection for OTPs, CVV, UPI, banking
 * credentials and PII, not just passwords and cards.
 *
 * PHASE 4 (§7): before-submit protection with an explicit
 * [ Cancel ] / [ Proceed anyway ] choice. The user stays in control — we never
 * silently block everything (spec §7).
 */

export type SensitiveKind =
  | "password"
  | "otp"
  | "card"
  | "cvv"
  | "upi"
  | "banking"
  | "personal";

/** §3 sensitive categories we can detect structurally. */
export const SENSITIVE_KINDS: readonly SensitiveKind[] = [
  "password",
  "otp",
  "card",
  "cvv",
  "upi",
  "banking",
  "personal",
];

export interface FormActionSignal {
  actionOrigin: string | null;
  isCrossOrigin: boolean;
  /** Which sensitive categories this form collects. Empty = not sensitive. */
  kinds: SensitiveKind[];
  containsPassword: boolean;
  containsPaymentFields: boolean;
}

// ---------------------------------------------------------------------------
// Injection-safe state (spec §31 + §19)
// ---------------------------------------------------------------------------

/**
 * State lives on `globalThis`, NOT in module scope.
 *
 * The background re-injects this script on every scan (via
 * `chrome.scripting.executeScript`), and scans are triggered by navigation,
 * tab activation, and SPA route changes — so the same document can receive
 * this file many times. Module-scoped `let` bindings are re-initialised on
 * each injection, which would silently reset `scanVerdict` to null and
 * disable before-submit protection mid-visit.
 *
 * Persisting state on the global object makes re-injection idempotent: the
 * verdict survives, and the event listeners are not stacked.
 */
interface ContentState {
  installed: boolean;
  scanVerdict: string | null;
  warningOverlay: HTMLDivElement | null;
  proceedAnyway: boolean;
}

const STATE_KEY = "__scamshieldContentState";

const host = globalThis as typeof globalThis & {
  [STATE_KEY]?: ContentState;
};

const state: ContentState = (host[STATE_KEY] ??= {
  installed: false,
  scanVerdict: null,
  warningOverlay: null,
  proceedAnyway: false,
});

export interface CollectedPageSignals {
  hasLoginForm: boolean;
  hasPasswordFieldsOnHttp: boolean;
  hasPaymentForm: boolean;
  urgencyLanguageCount: number;
  giveawayPatterns: number;
  fakeSecurityWarnings: number;
  externalScriptOrigins: string[];
  formActions: FormActionSignal[];
  /** §3: union of sensitive categories present anywhere on the page. */
  sensitiveKinds: SensitiveKind[];
  /** §6: credential/payment forms that submit to a different origin. */
  crossOriginSensitiveForms: number;
  /** §6: credential/payment forms submitting to an unrelated registrable domain. */
  offDomainSensitiveForms: number;
  /** §6: suspicious download links (executables / archives). */
  suspiciousDownloadCount: number;
}

const HIGH_RISK_VERDICTS = new Set(["SUSPICIOUS", "HIGH_RISK", "DANGEROUS"]);

// ---------------------------------------------------------------------------
// Structural selectors — attribute patterns only, never values.
// ---------------------------------------------------------------------------

/** OTP / one-time-code fields. */
const OTP_SELECTORS = [
  'input[autocomplete="one-time-code"]',
  'input[name*="otp" i]',
  'input[id*="otp" i]',
  'input[placeholder*="otp" i]',
  'input[name*="one-time" i]',
  'input[name*="verification code" i]',
  'input[placeholder*="verification code" i]',
  'input[name*="secure code" i]',
];

/** Payment card number fields. */
const CARD_SELECTORS = [
  'input[autocomplete="cc-number"]',
  'input[name*="card" i]',
  'input[id*="card" i]',
  'input[placeholder*="card number" i]',
];

/** CVV / CVC / security-code fields. */
const CVV_SELECTORS = [
  'input[autocomplete="cc-csc"]',
  'input[name*="cvv" i]',
  'input[id*="cvv" i]',
  'input[name*="cvc" i]',
  'input[name*="security code" i]',
  'input[placeholder*="cvv" i]',
];

/** UPI / Indian payment identifiers. */
const UPI_SELECTORS = [
  'input[name*="upi" i]',
  'input[id*="upi" i]',
  'input[placeholder*="upi" i]',
  'input[autocomplete="off"][name*="vpa" i]',
  'input[name*="virtual payment address" i]',
];

/** Banking credentials: net-banking id / PIN / account+routing. */
const BANKING_SELECTORS = [
  'input[name*="pin" i][type="password"]',
  'input[name*="netbanking" i]',
  'input[name*="net_banking" i]',
  'input[name*="routing" i]',
  'input[name*="account number" i]',
  'input[name*="accountnumber" i]',
  'input[name*="iban" i]',
];

/** Sensitive personal information: national ids, DOB, full address. */
const PERSONAL_SELECTORS = [
  'input[name*="aadhaar" i]',
  'input[id*="aadhaar" i]',
  'input[name*="ssn" i]',
  'input[name*="social security" i]',
  'input[name*="passport" i]',
  // Real sites spell this several ways: "date of birth", "dateOfBirth",
  // "date_of_birth", "dob", "dateOfBirthDay". Cover the common shapes.
  'input[name*="date of birth" i]',
  'input[name*="dateofbirth" i]',
  'input[name*="date_of_birth" i]',
  'input[id*="dateofbirth" i]',
  'input[name*="dob" i]',
  'input[name*="birthdate" i]',
  'input[name*="birth date" i]',
  // A phone/mobile number is personal data and is REPORTED as such, but it is
  // deliberately NOT high-impact: nearly every checkout and signup form asks
  // for one, so blocking submissions on it would be a mass false positive
  // (spec §3, §21 rule 8).
  'input[type="tel"]',
  'input[name*="mobile" i]',
  'input[name*="phone" i]',
];

/** §6: executable / archive downloads are a classic malware lure. */
const DOWNLOAD_EXTENSIONS =
  /\.(exe|msi|apk|scr|bat|cmd|jar|vbs|ps1|dmg|pkg|hta|iso|img|zip|rar|7z)$/i;

const KIND_SELECTORS: Array<[SensitiveKind, string[]]> = [
  ["password", ['input[type="password"]']],
  ["otp", OTP_SELECTORS],
  ["card", CARD_SELECTORS],
  ["cvv", CVV_SELECTORS],
  ["upi", UPI_SELECTORS],
  ["banking", BANKING_SELECTORS],
  ["personal", PERSONAL_SELECTORS],
];

/**
 * Categories that make a form high-impact enough to interrupt submission.
 *
 * `personal` is intentionally excluded: phone numbers and dates of birth are
 * personal data worth reporting, but they are requested by the majority of
 * legitimate sites, so treating them as a stop condition would train users to
 * dismiss the warning (spec §3: minimise false positives).
 *
 * `banking` is also excluded. Account / routing / IBAN-style fields appear on
 * legitimate bank logins AND on retailer checkout and billing pages, and the
 * selectors match attribute SUBSTRINGS — so an unrelated `name` containing
 * "pin" or "routing" trips it. Real banking phishing is caught by correlation
 * (unknown domain + credential collection + these fields), not by blocking
 * every form that looks financial.
 */
const HIGH_IMPACT_KINDS = new Set<SensitiveKind>([
  "password",
  "otp",
  "card",
  "cvv",
  "upi",
]);

/**
 * Structural detection of sensitive field CATEGORIES.
 *
 * Exported for tests. Reads only attributes and element types — never
 * `value`, never `textContent` of an input.
 */
export function kindsIn(root: ParentNode): SensitiveKind[] {
  const found: SensitiveKind[] = [];
  for (const [kind, selectors] of KIND_SELECTORS) {
    if (selectors.some((selector) => root.querySelector(selector) !== null)) {
      found.push(kind);
    }
  }
  return found;
}

export function containsSensitiveFormFields(form: HTMLFormElement): boolean {
  return kindsIn(form).some((kind) => HIGH_IMPACT_KINDS.has(kind));
}

// ---------------------------------------------------------------------------
// Before-submit protection (§7)
// ---------------------------------------------------------------------------

// NOTE: `scanVerdict`, `warningOverlay` and `proceedAnyway` live on the
// persisted `state` object (see ContentState above) rather than in module
// scope, so a re-injection cannot reset them mid-visit.

const WARNING_STYLE_ID = "scamshield-warning-style";

function ensureStyles(): void {
  if (document.getElementById(WARNING_STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = WARNING_STYLE_ID;
  style.textContent = `
    .scamshield-warning-overlay {
      position: fixed;
      z-index: 2147483646;
      left: 50%;
      top: 16px;
      transform: translateX(-50%);
      width: min(560px, calc(100vw - 24px));
      background: #7f1d1d;
      color: white;
      border-radius: 10px;
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
      padding: 12px 14px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }
    .scamshield-warning-overlay .scamshield-title {
      font-weight: 700;
      font-size: 15px;
      margin-bottom: 4px;
    }
    .scamshield-warning-overlay .scamshield-reasons {
      margin: 6px 0 10px;
      padding-left: 18px;
    }
    .scamshield-warning-overlay .scamshield-actions {
      display: flex;
      gap: 8px;
    }
    .scamshield-warning-overlay button {
      font: inherit;
      padding: 6px 14px;
      border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.5);
      background: rgba(255,255,255,0.12);
      color: #fff;
      cursor: pointer;
    }
    .scamshield-warning-overlay button[data-scamshield="cancel"] {
      background: #fff;
      color: #7f1d1d;
      font-weight: 700;
    }
  `;
  document.head.append(style);
}

function createOverlay(): HTMLDivElement {
  ensureStyles();
  const overlay = document.createElement("div");
  overlay.className = "scamshield-warning-overlay";
  overlay.setAttribute("role", "alertdialog");
  overlay.setAttribute("aria-live", "assertive");
  // document.body may not exist yet if injection ran during early page load.
  // A node cached while detached would swallow every future warning, so fall
  // back to documentElement — never leave protection invisible.
  (document.body ?? document.documentElement).append(overlay);
  return overlay;
}

/**
 * Explainable warning (spec §8): what happened, why it is suspicious, and
 * what the user can do — with an explicit choice so they remain in control.
 */
function showWarning(message: string, reasons: string[] = []): void {
  state.warningOverlay ??= createOverlay();
  state.warningOverlay.textContent = "";

  const title = document.createElement("div");
  title.className = "scamshield-title";
  title.textContent = "STOP — don't submit this form";
  state.warningOverlay.append(title);

  const what = document.createElement("div");
  what.textContent = message;
  state.warningOverlay.append(what);

  if (reasons.length > 0) {
    const list = document.createElement("ul");
    list.className = "scamshield-reasons";
    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      list.append(item);
    }
    state.warningOverlay.append(list);
  }

  const actions = document.createElement("div");
  actions.className = "scamshield-actions";

  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.dataset.scamshield = "cancel";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => {
    state.proceedAnyway = false;
    destroySubmissionWarning();
  });

  const proceed = document.createElement("button");
  proceed.type = "button";
  proceed.dataset.scamshield = "proceed";
  proceed.textContent = "Proceed anyway";
  proceed.addEventListener("click", () => {
    // The user stays in control (spec §7). We record the choice and stop
    // interfering with this page; we never silently block everything.
    state.proceedAnyway = true;
    destroySubmissionWarning();
  });

  actions.append(cancel, proceed);
  state.warningOverlay.append(actions);
}

function destroySubmissionWarning(): void {
  if (state.warningOverlay) {
    state.warningOverlay.remove();
    state.warningOverlay = null;
  }
}

function kindLabels(kinds: SensitiveKind[]): string {
  const readable: Record<SensitiveKind, string> = {
    password: "a password",
    otp: "a one-time password (OTP)",
    card: "card details",
    cvv: "a card security code (CVV)",
    upi: "UPI payment information",
    banking: "banking credentials",
    personal: "sensitive personal information",
  };
  return kinds.map((kind) => readable[kind]).join(", ");
}

function installSubmitGuard(): void {
  const guard = (form: HTMLFormElement): boolean => {
    if (!state.scanVerdict || !HIGH_RISK_VERDICTS.has(state.scanVerdict)) return false;
    // §7: an explicit "Proceed anyway" ends our interference.
    if (state.proceedAnyway) return false;
    const kinds = kindsIn(form).filter((kind) => HIGH_IMPACT_KINDS.has(kind));
    if (kinds.length === 0) return false;

    const reasons: string[] = [];
    if (state.scanVerdict === "DANGEROUS") {
      reasons.push("This website matches a known phishing or malware listing.");
    }
    if (kinds.includes("otp")) {
      reasons.push("Legitimate sites never ask for an OTP in a web page form.");
    }
    if (kinds.includes("cvv")) {
      reasons.push("Card security codes are not normally collected in browser forms.");
    }

    showWarning(
      `This website is asking for ${kindLabels(kinds)} while ScamShield has flagged the page.`,
      reasons,
    );
    return true;
  };

  document.addEventListener(
    "submit",
    (event) => {
      const target = event.target;
      if (!(target instanceof HTMLFormElement)) return;
      if (!guard(target)) return;
      event.preventDefault();
      event.stopPropagation();
    },
    true,
  );

  // Capture clicks before page handlers so a submit button cannot be used to
  // bypass the native submit event with custom JavaScript.
  document.addEventListener(
    "click",
    (event) => {
      if (!state.scanVerdict || !HIGH_RISK_VERDICTS.has(state.scanVerdict)) return;
      if (state.proceedAnyway) return;
      const target = event.target;
      if (!(target instanceof Element)) return;
      const control = target.closest("button, input");
      if (
        !(control instanceof HTMLButtonElement || control instanceof HTMLInputElement)
      )
        return;
      const type = control.getAttribute("type")?.toLowerCase() ?? "submit";
      if (type !== "submit") return;
      const form = control.form;
      if (!form || !guard(form)) return;

      event.preventDefault();
      event.stopImmediatePropagation();
    },
    true,
  );
}

function installNavigationObserver(): void {
  const state = globalThis as typeof globalThis & {
    __scamShieldContentInitialized?: boolean;
  };
  if (state.__scamShieldContentInitialized) return;
  state.__scamShieldContentInitialized = true;

  let lastUrl = globalThis.location.href;
  let contextAlive = true;

  /**
   * Tell the background worker the URL changed.
   *
   * `chrome.runtime.sendMessage` is unguarded here, which matters: `void`
   * discards the returned value but does NOT catch a synchronous throw or a
   * rejected promise. When the worker is asleep, unreachable, or the extension
   * context was invalidated by a reload, that surfaced as repeated uncaught
   * errors on SPA sites.
   *
   * Both the synchronous throw and the async rejection are handled, and a dead
   * context disables the observer instead of throwing on every tick.
   */
  const notify = (): void => {
    if (!contextAlive) return;
    const url = globalThis.location.href;
    if (url === lastUrl) return; // de-duplicate storms
    lastUrl = url;
    try {
      const result = chrome.runtime.sendMessage({
        type: "PAGE_NAVIGATED",
        url,
      });
      void Promise.resolve(result).catch(() => {
        // Worker unreachable or context invalidated — stop retrying rather
        // than flooding the host page's console on every navigation.
        contextAlive = false;
      });
    } catch {
      contextAlive = false;
    }
  };

  /**
   * SPA route-change detection by polling `location.href`.
   *
   * This deliberately does NOT monkey-patch history.pushState/replaceState.
   * Heavy SPAs call pushState continuously (chatgpt.com does so on every route
   * change and conversation switch), and patching a page-owned API both floods
   * the console and counts as invasive collection (spec §6, §16). The poll
   * below already observes every route change with no side effects on the host
   * page.
   */
  const POLL_INTERVAL_MS = 1_000;
  window.setInterval(() => {
    if (globalThis.location.href !== lastUrl) notify();
  }, POLL_INTERVAL_MS);

  globalThis.addEventListener("popstate", notify);
}

// ---------------------------------------------------------------------------
// Text / resource signal patterns (§6)
// ---------------------------------------------------------------------------

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

/** §6: fake KYC / verification lures common in payment scams. */
const FAKE_VERIFICATION_PATTERNS = [
  /kyc\s+(verification|update)\s+(is\s+)?(required|mandatory)/i,
  /verify\s+your\s+upi\s+id/i,
  /update\s+your\s+kyc\s+or\s+(your\s+)?account\s+will\s+be\s+(blocked|closed)/i,
  /complete\s+kyc\s+to\s+receive\s+(your\s+)?(refund|prize|reward)/i,
];

function countMatches(text: string, patterns: RegExp[]): number {
  return patterns.reduce(
    (count, pattern) => (pattern.test(text) ? count + 1 : count),
    0,
  );
}

const MAX_TEXT_BYTES = 50_000;

/**
 * Bounded read of rendered page text.
 *
 * Returns "" rather than throwing: pattern counts are supporting evidence, so
 * losing them must never abort the whole collection.
 */
function readVisibleText(): string {
  try {
    return (document.body?.innerText ?? "").slice(0, MAX_TEXT_BYTES);
  } catch {
    return "";
  }
}

/** Registrable-domain heuristic for "is this a different site entirely". */
function baseDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".");
  return parts.slice(-2).join(".");
}

function collectSignals(): CollectedPageSignals {
  const isHttps = globalThis.location.protocol === "https:";

  const pageKinds = kindsIn(document);
  const hasLoginForm =
    document.querySelector('input[type="password"]') !== null;

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

  // §6: count risky download lures (structure only, never fetch them).
  const suspiciousDownloadCount = Array.from(
    document.querySelectorAll("a[href]"),
  ).filter((a) => DOWNLOAD_EXTENSIONS.test(a.getAttribute("href") ?? "")).length;

  // Visible text scan — bounded to avoid expensive traversal on huge pages.
  // `innerText` forces a synchronous layout/reflow, which is very costly on
  // large SPAs, so it is guarded: a page that throws here must not fail the
  // entire signal collection.
  const bodyText = readVisibleText();

  // §22–§23: form-action origin analysis. Structural attributes only —
  // never reads input values.
  const pageOrigin = globalThis.location.origin;
  const pageBase = baseDomain(globalThis.location.hostname);
  const formActions: FormActionSignal[] = [];
  let crossOriginSensitiveForms = 0;
  let offDomainSensitiveForms = 0;

  for (const form of Array.from(document.querySelectorAll("form")).slice(0, 20)) {
    const kinds = kindsIn(form).filter((kind) => HIGH_IMPACT_KINDS.has(kind));
    if (kinds.length === 0) continue;

    let actionOrigin: string | null = null;
    const rawAction = form.getAttribute("action");
    if (rawAction) {
      try {
        actionOrigin = new URL(rawAction, globalThis.location.href).origin;
      } catch {
        actionOrigin = null;
      }
    } else {
      actionOrigin = pageOrigin; // submits to current URL
    }

    const isCrossOrigin = actionOrigin !== null && actionOrigin !== pageOrigin;

    // A sibling subdomain is common on legitimate sites (accounts.google.com
    // for a page on google.com); an unrelated registrable domain is not.
    // Count the stronger signal separately so rules can weight it.
    let isOffDomain = false;
    if (actionOrigin) {
      try {
        isOffDomain = baseDomain(new URL(actionOrigin).hostname) !== pageBase;
      } catch {
        isOffDomain = false;
      }
    }

    formActions.push({
      actionOrigin,
      isCrossOrigin,
      kinds,
      containsPassword: kinds.includes("password"),
      containsPaymentFields: kinds.some(
        (kind) => kind === "card" || kind === "cvv" || kind === "upi",
      ),
    });

    if (isCrossOrigin) crossOriginSensitiveForms += 1;
    if (isOffDomain) offDomainSensitiveForms += 1;
  }

  return {
    hasLoginForm,
    hasPasswordFieldsOnHttp: !isHttps && hasLoginForm,
    hasPaymentForm: pageKinds.some(
      (kind) => kind === "card" || kind === "cvv" || kind === "upi",
    ),
    urgencyLanguageCount: countMatches(bodyText, URGENCY_PATTERNS),
    // §14: fake KYC / refund lures count with the deceptive-content signal.
    giveawayPatterns:
      countMatches(bodyText, GIVEAWAY_PATTERNS) +
      countMatches(bodyText, FAKE_VERIFICATION_PATTERNS),
    fakeSecurityWarnings: countMatches(bodyText, FAKE_WARNING_PATTERNS),
    externalScriptOrigins,
    formActions,
    sensitiveKinds: pageKinds,
    crossOriginSensitiveForms,
    offDomainSensitiveForms,
    suspiciousDownloadCount,
  };
}

// Re-injected on every scan, so installation MUST be idempotent. Registering
// the listener and guards again would double every submit/click interception
// and, worse, would leave the persisted verdict in place but stack handlers on
// top of it. `state.installed` is stored on globalThis, so it survives the
// re-initialisation that a fresh module evaluation performs.
if (!state.installed) {
  state.installed = true;

  // Answers signal-collection and risk-state requests over the extension
  // messaging channel.
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

  if (
    typeof message === "object" &&
    message !== null &&
    (message as { type?: string }).type === "SET_SCAN_RISK_STATE"
  ) {
    const payload = message as {
      type: string;
      verdict?: string;
      showWarning?: boolean;
    };
    state.scanVerdict = payload.verdict ?? null;
    // A new verdict resets the user's previous "proceed anyway" choice.
    state.proceedAnyway = false;
    if (!state.scanVerdict || !HIGH_RISK_VERDICTS.has(state.scanVerdict)) {
      destroySubmissionWarning();
      return false;
    }
    if (payload.showWarning) {
      showWarning(
        "ScamShield detected a suspicious or high-risk page. Do not submit passwords, payments, OTPs, or UPI details here.",
      );
    }
    return false;
  }

  // Return true only when responding asynchronously — here it's synchronous.
    return false;
  });

  installSubmitGuard();
  installNavigationObserver();
}
