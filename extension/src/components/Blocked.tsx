import { useState } from "react";
import { VERDICT_LABELS, type RiskVerdict } from "@shared/index";

interface BlockedPageProps {
  url: string;
  verdict: RiskVerdict;
  onGoBack: () => void;
  onContinue: () => void;
}

/**
 * Full-tab block page. Shown ONLY for the worst auto-scan verdicts —
 * DANGEROUS with a score at/below FULL_BLOCK_SCORE_THRESHOLD (the cases
 * with confirmed threat matches or overwhelming evidence). A badge or a
 * banner is too quiet for these, and dead/unresolvable domains (the classic
 * lookalike-typo case) cannot show in-page UI at all, so taking over the tab
 * is the only channel that always reaches the user. The user stays in
 * control: leaving is one click, and continuing records a session bypass.
 */
export function BlockedPage({ url, verdict, onGoBack, onContinue }: BlockedPageProps) {
  const [leaving, setLeaving] = useState(false);

  let hostname = url;
  try {
    hostname = new URL(url).hostname;
  } catch {
    // Show the raw value rather than nothing.
  }

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[560px] flex-col items-center justify-center bg-gradient-to-b from-red-950 via-slate-950 to-slate-950 px-6 py-10 text-center text-white">
      <span
        aria-hidden="true"
        className="flex h-16 w-16 items-center justify-center rounded-3xl bg-gradient-to-br from-red-500 to-red-700 text-3xl font-bold shadow-lg shadow-red-900/50"
      >
        !
      </span>
      <p className="mt-5 text-[11px] font-bold uppercase tracking-widest text-red-400">
        ScamShield blocked this site
      </p>
      <h1 className="mt-1 text-2xl font-bold tracking-tight">
        {VERDICT_LABELS[verdict]}
      </h1>
      <p className="mt-2 max-w-[420px] break-all font-mono text-xs text-slate-400">
        {hostname}
      </p>
      <p className="mt-3 max-w-[440px] text-sm leading-relaxed text-slate-300">
        Multiple strong indicators of phishing or malware were found. Do not
        enter passwords, card details, OTPs, or personal information — leave
        this website.
      </p>
      <div className="mt-6 flex w-full max-w-[320px] flex-col gap-2">
        <button
          type="button"
          disabled={leaving}
          onClick={() => {
            setLeaving(true);
            onGoBack();
          }}
          className="min-h-[42px] w-full rounded-xl bg-gradient-to-b from-red-500 to-red-700 text-sm font-bold text-white shadow-md shadow-red-900/40 transition-all duration-150 hover:from-red-400 hover:to-red-600 active:scale-[0.99] disabled:opacity-60"
        >
          Go back to safety
        </button>
        <button
          type="button"
          onClick={onContinue}
          className="min-h-[42px] w-full rounded-xl border border-white/15 bg-white/5 text-sm font-semibold text-slate-300 transition-colors hover:bg-white/10 hover:text-white"
        >
          Continue anyway
        </button>
      </div>
      <p className="mt-6 text-[10px] leading-relaxed text-slate-500">
        ScamShield provides probabilistic risk indicators, not guarantees.
      </p>
    </div>
  );
}
