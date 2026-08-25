interface ScanProgressProps {
  step: string;
}

/** Real scan progress indicator (spec §19) — no artificial delays. */
export function ScanProgress({ step }: ScanProgressProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center gap-3 py-8"
    >
      <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-neutral-200 border-t-shield-500 dark:border-neutral-800 dark:border-t-shield-500" />
      <p className="text-sm text-neutral-600 dark:text-neutral-400">{step}…</p>
    </div>
  );
}
