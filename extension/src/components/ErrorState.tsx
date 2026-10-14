import type { ReactNode } from "react";

interface ErrorStateProps {
  title: string;
  message: string;
  action?: ReactNode;
}

export function ErrorState({ title, message, action }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center gap-2 rounded-2xl border border-red-500/25 bg-gradient-to-b from-red-500/[0.08] to-transparent p-5 text-center shadow-sm"
    >
      <span
        aria-hidden="true"
        className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 text-lg font-bold text-red-500"
      >
        !
      </span>
      <p className="text-sm font-bold tracking-tight text-red-800 dark:text-red-200">{title}</p>
      <p className="max-w-[280px] text-xs leading-relaxed text-red-700/80 dark:text-red-300/80">
        {message}
      </p>
      {action}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  message,
}: {
  icon: string;
  title: string;
  message: string;
}) {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-slate-300/80 px-6 py-10 text-center dark:border-white/15">
      <span
        aria-hidden="true"
        className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-500/[0.08] text-xl font-semibold text-slate-400 dark:text-slate-500"
      >
        {icon}
      </span>
      <p className="mt-1 text-sm font-bold tracking-tight text-slate-800 dark:text-slate-100">
        {title}
      </p>
      <p className="max-w-[260px] text-xs leading-relaxed text-slate-500 dark:text-slate-400">
        {message}
      </p>
    </div>
  );
}
