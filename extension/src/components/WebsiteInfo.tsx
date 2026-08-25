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
    <div className="rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center justify-between px-3 py-2.5 text-left"
      >
        <span className="min-w-0">
          <span className="block truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
            {info.hostname}
          </span>
          <span className="text-[11px] uppercase tracking-wide text-neutral-400 dark:text-neutral-500">
            {info.protocol}
          </span>
        </span>
        <span aria-hidden="true" className="ml-2 text-neutral-400">
          {open ? "▾" : "▸"}
        </span>
      </button>
      {open && (
        <dl className="space-y-1 border-t border-neutral-200 px-3 py-2 text-xs dark:border-neutral-800">
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
