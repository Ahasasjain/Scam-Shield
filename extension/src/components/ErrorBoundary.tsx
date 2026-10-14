import { Component, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  crashed: boolean;
}

/**
 * Last-resort crash containment for the popup/side panel. A render crash
 * without a boundary unmounts the entire UI into a blank panel with no
 * recovery path; the boundary keeps the shell alive with a reload affordance.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { crashed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { crashed: true };
  }

  override componentDidCatch(): void {
    // Intentionally not logged anywhere: the extension has no telemetry, and
    // scan history must never carry error payloads (spec §16).
  }

  override render(): ReactNode {
    if (!this.state.crashed) return this.props.children;

    return (
      <div className="mx-auto flex min-h-[320px] w-full max-w-[480px] flex-col items-center justify-center gap-2 p-6 text-center">
        <span
          aria-hidden="true"
          className="flex h-12 w-12 items-center justify-center rounded-2xl bg-red-500/10 text-xl font-bold text-red-500"
        >
          !
        </span>
        <p className="text-sm font-bold tracking-tight text-slate-900 dark:text-white">
          Something went wrong
        </p>
        <p className="max-w-[280px] text-xs leading-relaxed text-slate-500 dark:text-slate-400">
          ScamShield hit an unexpected display error. Your protection settings
          are unaffected.
        </p>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="mt-1 min-h-[36px] rounded-xl bg-gradient-to-b from-emerald-500 to-emerald-700 px-5 text-sm font-bold text-white shadow-md shadow-emerald-600/25 transition-all duration-150 hover:from-emerald-600 hover:to-emerald-700 active:scale-[0.99]"
        >
          Reload panel
        </button>
      </div>
    );
  }
}
