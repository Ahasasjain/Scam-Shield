interface AIModeToggleProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
}

/**
 * Prominent AI detection ON/OFF switch (spec §7). Persisted via
 * chrome.storage.local in the background worker.
 */
export function AIModeToggle({ enabled, onChange, disabled }: AIModeToggleProps) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-neutral-200 bg-white px-3 py-2.5 dark:border-neutral-800 dark:bg-neutral-900">
      <div>
        <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
          AI Detection
        </p>
        <p className="text-[11px] text-neutral-500 dark:text-neutral-400">
          {enabled
            ? "Sends minimal security signals to our API"
            : "Rule-based scan only — nothing leaves your browser"}
        </p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        aria-label="AI Detection"
        disabled={disabled}
        onClick={() => onChange(!enabled)}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors duration-200 focus-visible:outline-2 disabled:opacity-50 ${
          enabled ? "bg-violet-600" : "bg-neutral-300 dark:bg-neutral-700"
        }`}
      >
        <span
          aria-hidden="true"
          className={`inline-block h-4.5 w-4.5 transform rounded-full bg-white shadow transition-transform duration-200 ${
            enabled ? "translate-x-[22px]" : "translate-x-1"
          }`}
          style={{ height: 18, width: 18 }}
        />
      </button>
    </div>
  );
}
