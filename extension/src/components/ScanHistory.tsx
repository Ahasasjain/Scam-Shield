import type { HistoryEntry } from "@shared/index";
import { RiskBadge } from "./RiskBadge";
import { EmptyState } from "./ErrorState";
import type { RiskLevel } from "@shared/index";

interface ScanHistoryProps {
  history: HistoryEntry[];
  onClear: () => void;
}

/** Local scan history (spec §24) — hostname/score/risk/time only. */
export function ScanHistory({ history, onClear }: ScanHistoryProps) {
  if (history.length === 0) {
    return (
      <EmptyState
        icon="🕘"
        title="No scan history yet"
        message="Scans you run will appear here, stored only on this device."
      />
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
          Recent scans
        </h3>
        <button
          type="button"
          onClick={onClear}
          className="text-xs font-medium text-red-600 hover:underline dark:text-red-400"
        >
          Clear history
        </button>
      </div>
      <ul className="space-y-1.5" aria-label="Scan history">
        {history.map((entry, index) => (
          <li
            key={`${entry.scannedAt}-${index}`}
            className="flex items-center justify-between rounded-lg border border-neutral-200 bg-white px-3 py-2 text-xs dark:border-neutral-800 dark:bg-neutral-900"
          >
            <div className="min-w-0">
              <p className="truncate font-medium text-neutral-900 dark:text-neutral-100">
                {entry.hostname}
              </p>
              <p className="text-[10px] text-neutral-500 dark:text-neutral-400">
                {new Date(entry.scannedAt).toLocaleString()}
              </p>
            </div>
            <div className="ml-2 flex shrink-0 items-center gap-2">
              <span className="font-semibold tabular-nums text-neutral-700 dark:text-neutral-300">
                {entry.score}
              </span>
              <RiskBadge level={entry.riskLevel as RiskLevel} />
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
