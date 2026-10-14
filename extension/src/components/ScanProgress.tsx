interface ScanProgressProps {
  step: string;
}

/** Real scan progress indicator (spec §19) — no artificial delays. */
export function ScanProgress({ step }: ScanProgressProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-[220px] flex-col items-center justify-center gap-3 rounded-2xl border border-slate-200/80 bg-white py-8 shadow-sm dark:border-white/10 dark:bg-white/5"
    >
      <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-slate-200 border-t-emerald-500 dark:border-white/10 dark:border-t-emerald-400" />
      <p className="text-sm font-medium tabular-nums text-slate-500 dark:text-slate-400">{step}…</p>
    </div>
  );
}
