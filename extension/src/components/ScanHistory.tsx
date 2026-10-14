import { useMemo, useState } from "react";
import {
  VERDICT_LABELS,
  type HistoryEntry,
  type RiskVerdict,
} from "@shared/index";
import { EmptyState } from "./ErrorState";

interface ScanHistoryProps {
  history: HistoryEntry[];
  onClear: () => void;
}

/** Spec §17 UX states: Protected / Be Careful / Stop. */
const VERDICT_DISPLAY: Record<
  RiskVerdict,
  { state: string; dot: string; pill: string }
> = {
  SAFE: {
    state: "Protected",
    dot: "bg-emerald-500",
    pill: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25",
  },
  LOW_RISK: {
    state: "Protected",
    dot: "bg-emerald-500",
    pill: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25",
  },
  SUSPICIOUS: {
    state: "Be careful",
    dot: "bg-amber-500",
    pill: "bg-amber-500/10 text-amber-700 dark:text-amber-300 ring-amber-500/25",
  },
  HIGH_RISK: {
    state: "Be careful",
    dot: "bg-orange-500",
    pill: "bg-orange-500/10 text-orange-700 dark:text-orange-300 ring-orange-500/25",
  },
  DANGEROUS: {
    state: "Stop",
    dot: "bg-red-500",
    pill: "bg-red-500/10 text-red-700 dark:text-red-300 ring-red-500/25",
  },
  UNKNOWN: {
    state: "Not enough information",
    dot: "bg-slate-400",
    pill: "bg-slate-500/10 text-slate-600 dark:text-slate-300 ring-slate-500/25",
  },
};

function dayLabel(timestamp: number): string {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86_400_000);
  const sameDay = (a: Date, b: Date) =>
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate();
  if (sameDay(date, today)) return "Today";
  if (sameDay(date, yesterday)) return "Yesterday";
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: date.getFullYear() === today.getFullYear() ? undefined : "numeric",
  });
}

function isRiskVerdict(value: unknown): value is RiskVerdict {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(VERDICT_LABELS, value)
  );
}

/**
 * Security timeline (spec §18): website, time, verdict, score, the important
 * evidence, and the analysis mode — so a past scan can be understood at a
 * glance without re-scanning.
 *
 * Stability notes: rows use fixed-size CSS dots (never emoji, whose font
 * metrics shift row width), the Details toggle has a fixed minimum width so
 * its label swap never reflows the row, and detail panels mount only on
 * demand with an opacity-only animation (no transform, no layout thrash).
 */
export function ScanHistory({ history, onClear }: ScanHistoryProps) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const groups = useMemo(() => {
    const map = new Map<string, HistoryEntry[]>();
    for (const entry of history) {
      const key = dayLabel(entry.scannedAt);
      const bucket = map.get(key);
      if (bucket) bucket.push(entry);
      else map.set(key, [entry]);
    }
    return [...map.entries()];
  }, [history]);

  if (history.length === 0) {
    return (
      <EmptyState
        icon="◷"
        title="No scan history yet"
        message="Scans you run will appear here, stored only on this device."
      />
    );
  }

  return (
    <div className="ss-anchor space-y-4">
      <div className="flex min-h-[32px] items-center justify-between gap-2">
        <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
          Security timeline
        </h2>
        <button
          type="button"
          onClick={onClear}
          className="rounded-lg px-2 py-1 text-xs font-semibold text-red-600 transition-colors hover:bg-red-500/10 dark:text-red-400"
        >
          Clear history
        </button>
      </div>

      {groups.map(([day, entries]) => (
        <section key={day} aria-label={day}>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-500">
            {day}
          </h3>
          <ul className="space-y-2">
            {entries.map((entry, index) => {
              const key = `${entry.scannedAt}-${entry.hostname}-${index}`;
              // New entries store `verdict`; older ones only have the legacy
              // `riskLevel` string, which may itself hold a RiskVerdict.
              const verdict: RiskVerdict | null = isRiskVerdict(entry.verdict)
                ? entry.verdict
                : isRiskVerdict(entry.riskLevel)
                  ? entry.riskLevel
                  : null;
              const display = verdict ? VERDICT_DISPLAY[verdict] : null;
              const hasDetail =
                (entry.evidence?.length ?? 0) > 0 || entry.analysisMode !== undefined;
              const isOpen = expanded === key;

              return (
                <li
                  key={key}
                  className="rounded-2xl border border-slate-200/80 bg-white px-3.5 py-3 shadow-sm transition-colors hover:border-slate-300 dark:border-white/10 dark:bg-white/5 dark:hover:border-white/20"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-2.5">
                      <span
                        aria-hidden="true"
                        className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${display?.dot ?? "bg-slate-400"}`}
                      />
                      <div className="min-w-0">
                        <p className="truncate text-[13px] font-semibold text-slate-900 dark:text-white">
                          <span title={entry.url ?? entry.hostname}>
                            {entry.url ?? entry.hostname}
                          </span>
                        </p>
                        <p className="mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[11px] text-slate-500 dark:text-slate-400">
                          {display ? (
                            <span
                              className={`inline-flex items-center rounded-full px-2 py-0.5 font-semibold ring-1 ring-inset ${display.pill}`}
                            >
                              {display.state}
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded-full bg-slate-500/10 px-2 py-0.5 font-semibold text-slate-600 ring-1 ring-inset ring-slate-500/25 dark:text-slate-300">
                              Scanned
                            </span>
                          )}
                          <span className="tabular-nums">
                            {new Date(entry.scannedAt).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}
                          </span>
                          <span aria-hidden="true">·</span>
                          <span className="tabular-nums font-medium">
                            score {entry.score}
                          </span>
                        </p>
                      </div>
                    </div>
                    {hasDetail && (
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : key)}
                        aria-expanded={isOpen}
                        aria-label={`${isOpen ? "Hide" : "Show"} details for ${entry.hostname}`}
                        className="min-w-[64px] shrink-0 rounded-lg px-2 py-1 text-center text-[11px] font-semibold text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-white/10 dark:hover:text-slate-200"
                      >
                        {isOpen ? "Hide" : "Details"}
                      </button>
                    )}
                  </div>

                  {isOpen && (
                    <div className="ss-animate-in mt-2.5 space-y-1.5 border-t border-slate-100 pt-2.5 text-xs dark:border-white/10">
                      {verdict && (
                        <p className="font-medium text-slate-600 dark:text-slate-300">
                          {VERDICT_LABELS[verdict]}
                        </p>
                      )}
                      {entry.analysisMode && (
                        <p className="text-slate-500 dark:text-slate-400">
                          Analysis mode:{" "}
                          {entry.analysisMode === "ai-enhanced"
                            ? "deterministic rules + AI analyst"
                            : entry.analysisMode === "degraded"
                              ? "deterministic rules (AI unavailable)"
                              : "deterministic rules only"}
                        </p>
                      )}
                      {entry.evidence && entry.evidence.length > 0 && (
                        <ul className="space-y-1">
                          {entry.evidence.map((item) => (
                            <li
                              key={item}
                              className="flex items-start gap-1.5 text-slate-600 dark:text-slate-300"
                            >
                              <span
                                aria-hidden="true"
                                className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-400"
                              />
                              {item}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}
