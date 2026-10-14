import { useState } from "react";

interface WebsiteInfoProps {
  url: string;
  scanDurationMs?: number;
}

function formatUrl(url: string): {
  hostname: string;
  protocol: string;
  domain: string;
} {
  try {
    const parsed = new URL(url);
    const parts = parsed.hostname.split(".");
    return {
      hostname: parsed.hostname,
      protocol: parsed.protocol.replace(":", ""),
      domain: parts.slice(-2).join("."),
    };
  } catch {
    return { hostname: url, protocol: "—", domain: "—" };
  }
}

/** Expandable card with actual site metadata and real scan time (spec §20). */
export function WebsiteInfo({ url, scanDurationMs }: WebsiteInfoProps) {
  const [open, setOpen] = useState(false);
  const info = formatUrl(url);

  return (
    <div className="rounded-2xl border border-slate-200/80 bg-white shadow-sm dark:border-white/10 dark:bg-white/5">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex min-h-[52px] w-full items-center justify-between gap-2 px-3.5 py-2.5 text-left"
      >
        <span className="min-w-0">
          <span className="block truncate text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
            {info.hostname}
          </span>
          <span className="mt-0.5 block text-[10px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">
            {info.protocol}
          </span>
        </span>
        <span
          aria-hidden="true"
          className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-xs text-slate-500 transition-transform duration-150 dark:bg-white/10 dark:text-slate-400 ${open ? "rotate-180" : ""}`}
        >
          ▾
        </span>
      </button>
      {open && (
        <dl className="ss-animate-in space-y-1.5 border-t border-slate-100 px-3.5 py-3 text-xs dark:border-white/10">
          <div className="flex justify-between gap-2">
            <dt className="text-neutral-500 dark:text-neutral-400">Hostname</dt>
            <dd className="truncate font-medium text-neutral-800 dark:text-neutral-200">
              {info.hostname}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-neutral-500 dark:text-neutral-400">Domain</dt>
            <dd className="font-medium text-neutral-800 dark:text-neutral-200">
              {info.domain}
            </dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-neutral-500 dark:text-neutral-400">Protocol</dt>
            <dd className="font-medium uppercase text-neutral-800 dark:text-neutral-200">
              {info.protocol}
            </dd>
          </div>
          {typeof scanDurationMs === "number" && (
            <div className="flex justify-between gap-2">
              <dt className="text-neutral-500 dark:text-neutral-400">Scan time</dt>
              <dd className="font-medium tabular-nums text-neutral-800 dark:text-neutral-200">
                {scanDurationMs} ms
              </dd>
            </div>
          )}
        </dl>
      )}
    </div>
  );
}
