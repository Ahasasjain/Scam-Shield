import { useState } from "react";

/**
 * "What ScamShield sees" (spec §16).
 *
 * A user-facing privacy explanation. The spec requires this to clearly state:
 * what is analysed, what leaves the device, when AI is used, and what is
 * NEVER collected. The last list is the important one: it is the concrete
 * promise the implementation actually upholds.
 */

const ANALYSED: Array<{ title: string; body: string }> = [
  {
    title: "The address you visited",
    body: "Hostname, domain, whether the page uses HTTPS, URL length and structure, and the page path with sensitive segments redacted.",
  },
  {
    title: "The shape of the page",
    body: "Whether the page has login, payment, OTP, UPI, or banking fields — never what you type into them. Plus the origins its forms submit to.",
  },
  {
    title: "Page wording patterns",
    body: "Counts of urgency, prize, and fake-warning phrases. Only the count is kept, not the surrounding page text.",
  },
  {
    title: "Domain registration",
    body: "Approximate domain age from the public RDAP registry, and who the registrar is.",
  },
  {
    title: "Threat intelligence",
    body: "The domain is checked against Google Safe Browsing, the OpenPhish feed, and a small built-in list of known lookalike domains.",
  },
];

const NEVER_COLLECTED: string[] = [
  "Passwords",
  "One-time passwords (OTPs) and PINs",
  "Credit or debit card numbers",
  "Card security codes (CVV/CVC)",
  "UPI identifiers and payment values",
  "Cookies or session tokens",
  "Form field contents of any kind",
  "Full page text",
  "Files from your device",
  "Your browsing history beyond the last 50 scans on this device",
];

export function PrivacyExplainer() {
  const [open, setOpen] = useState(false);

  return (
    <section className="rounded-2xl border border-slate-200/80 bg-white p-3.5 shadow-sm dark:border-white/10 dark:bg-white/5">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-2 text-left text-sm font-semibold"
      >
        <span>What ScamShield sees</span>
        <span aria-hidden="true" className="text-xs text-neutral-500">
          {open ? "▾" : "▸"}
        </span>
      </button>

      {!open && (
        <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-400">
          ScamShield analyses the structure of a page, never what you type into
          it. Full details below.
        </p>
      )}

      {open && (
        <div className="mt-3 space-y-4 text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
          <section>
            <h3 className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
              What is analysed
            </h3>
            <ul className="space-y-2">
              {ANALYSED.map((item) => (
                <li key={item.title}>
                  <span className="font-medium">{item.title}.</span> {item.body}
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h3 className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
              What leaves your device
            </h3>
            <p>
              Only the sanitised security metadata above is sent to the
              ScamShield analysis service, and only when the local evidence
              shows a case is genuinely ambiguous. Your API keys stay on the
              server. Query strings, URL fragments, and sensitive path
              segments such as password-reset tokens or email addresses are
              redacted before anything is transmitted.
            </p>
          </section>

          <section>
            <h3 className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
              When AI is used
            </h3>
            <p>
              AI is a second opinion, not the detector. It is only consulted
              when deterministic evidence is ambiguous, and it can never
              downgrade a confirmed threat-intelligence match. Ordinary
              browsing of legitimate sites does not trigger an AI call.
            </p>
          </section>

          <section>
            <h3 className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
              Never collected, never transmitted
            </h3>
            <ul className="list-disc space-y-1 pl-4">
              {NEVER_COLLECTED.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>

          <section>
            <h3 className="mb-1 font-semibold text-neutral-900 dark:text-neutral-100">
              What is stored
            </h3>
            <p>
              Settings and the last {50} scan results (address, timestamp,
              verdict, score, and summary reasons) are kept in this browser
              profile only. There is no analytics or third-party tracking, and
              nothing is sold or shared.
            </p>
          </section>
        </div>
      )}
    </section>
  );
}
