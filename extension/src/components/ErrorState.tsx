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
      className="ss-animate-in flex flex-col items-center gap-2 rounded-xl border border-red-200 bg-red-50 p-4 text-center dark:border-red-900 dark:bg-red-950/40"
    >
      <span aria-hidden="true" className="text-2xl">
        ⚠️
      </span>
      <p className="text-sm font-semibold text-red-800 dark:text-red-300">{title}</p>
      <p className="text-xs leading-relaxed text-red-700 dark:text-red-400">
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
    <div className="flex flex-col items-center gap-1.5 py-10 text-center">
      <span aria-hidden="true" className="text-3xl opacity-70">
        {icon}
      </span>
      <p className="text-sm font-medium text-neutral-800 dark:text-neutral-200">
        {title}
      </p>
      <p className="max-w-[240px] text-xs leading-relaxed text-neutral-500 dark:text-neutral-400">
        {message}
      </p>
    </div>
  );
}
