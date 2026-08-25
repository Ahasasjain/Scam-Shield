import { useState } from "react";
import type { AiAnalysisResult } from "@shared/index";

interface AIAnalysisProps {
  ai:
    | { status: "enabled"; result: unknown }
    | { status: "unavailable"; reason: string }
    | { status: "disabled" };
}

/**
 * AI analysis card (spec §14–§18). Renders validated AI results, the
 * graceful-unavailable message, or nothing when AI is off.
 */
export function AIAnalysis({ ai }: AIAnalysisProps) {
  const [expanded, setExpanded] = useState(true);

  if (ai.status === "disabled") return null;

  if (ai.status === "unavailable") {
    return (
      <section
        aria-label="AI analysis unavailable"
        className="ss-animate-in rounded-xl border border-neutral-200 bg-neutral-50 p-3 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-400"
      >
        <p className="font-medium text-neutral-800 dark:text-neutral-200">
          AI analysis unavailable.
        </p>
        <p className="mt-1">{ai.reason}</p>
        <p className="mt-1">Your rule-based security scan is still available.</p>
      </section>
    );
  }

  const result = ai.result as AiAnalysisResult;

  return (
    <section
      aria-label="AI analysis"
      className="ss-animate-in rounded-xl border border-violet-200 bg-violet-50/60 p-3 dark:border-violet-900 dark:bg-violet-950/40"
    >
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between text-left"
      >
        <h3 className="text-sm font-semibold text-violet-900 dark:text-violet-300">
          AI Analysis
        </h3>
        <span className="flex items-center gap-2 text-xs text-violet-700 dark:text-violet-400">
          <span className="tabular-nums">
            Confidence {Math.round(result.confidence)}%
          </span>
          <span aria-hidden="true">{expanded ? "▾" : "▸"}</span>
        </span>
      </button>

      {expanded && (
        <div className="mt-2 space-y-2">
          <p className="text-xs leading-relaxed text-neutral-700 dark:text-neutral-300">
            {result.summary}
          </p>
          {result.indicators.length > 0 && (
            <ul className="space-y-1.5">
              {result.indicators.map((indicator) => (
                <li
                  key={indicator.id}
                  className="rounded-lg bg-white p-2 text-xs dark:bg-neutral-900"
                >
                  <p className="font-medium text-neutral-900 dark:text-neutral-100">
                    {indicator.title}{" "}
                    <span className="font-normal text-neutral-500 dark:text-neutral-400">
                      (−{indicator.points})
                    </span>
                  </p>
                  <p className="mt-0.5 text-neutral-600 dark:text-neutral-400">
                    {indicator.description}
                  </p>
                </li>
              ))}
            </ul>
          )}
          <p className="rounded-lg bg-white p-2 text-xs font-medium text-neutral-800 dark:bg-neutral-900 dark:text-neutral-200">
            Recommendation: {result.recommendation}
          </p>
        </div>
      )}
    </section>
  );
}
