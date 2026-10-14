import type { ExtensionSettings, ThemeSetting } from "@shared/index";

interface SettingsPanelProps {
  settings: ExtensionSettings;
  onUpdate: (patch: Partial<ExtensionSettings>) => void;
  onReset: () => void;
}

const THEMES: ThemeSetting[] = ["light", "dark", "system"];

/** Settings (spec §25) — honest privacy explanation, no overclaiming. */
export function SettingsPanel({ settings, onUpdate, onReset }: SettingsPanelProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3 rounded-2xl border border-slate-200/80 bg-white px-4 py-3 shadow-sm dark:border-white/10 dark:bg-white/5">
        <span>
          <span className="block text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
            Automatic scanning
          </span>
          <span className="mt-0.5 block text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
            Scan pages automatically as you browse
          </span>
        </span>
        <button
          type="button"
          role="switch"
          aria-checked={settings.autoScan}
          aria-label="Automatic scanning"
          onClick={() => onUpdate({ autoScan: !settings.autoScan })}
          className={`relative h-6 w-11 shrink-0 rounded-full transition-colors duration-150 ${
            settings.autoScan ? "bg-emerald-500" : "bg-slate-300 dark:bg-white/15"
          }`}
        >
          <span
            aria-hidden="true"
            className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all duration-150 ${
              settings.autoScan ? "left-[22px]" : "left-0.5"
            }`}
          />
        </button>
      </div>

      <div className="rounded-2xl border border-slate-200/80 bg-white px-4 py-3 shadow-sm dark:border-white/10 dark:bg-white/5">
        <p className="text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
          Theme
        </p>
        <div
          role="radiogroup"
          aria-label="Theme"
          className="mt-2 grid grid-cols-3 gap-1.5 rounded-xl bg-slate-100 p-1 dark:bg-white/5"
        >
          {THEMES.map((theme) => (
            <button
              key={theme}
              type="button"
              role="radio"
              aria-checked={settings.theme === theme}
              onClick={() => onUpdate({ theme })}
              className={`min-h-[32px] rounded-lg px-2 py-1.5 text-xs font-semibold capitalize transition-all duration-150 ${
                settings.theme === theme
                  ? "bg-white text-slate-900 shadow-sm dark:bg-white/10 dark:text-white"
                  : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
            >
              {theme}
            </button>
          ))}
        </div>
      </div>

      <section className="rounded-2xl border border-slate-200/80 bg-white p-4 text-xs leading-relaxed text-slate-500 shadow-sm dark:border-white/10 dark:bg-white/5 dark:text-slate-400">
        <h3 className="mb-1 text-sm font-semibold tracking-tight text-slate-900 dark:text-white">
          Privacy
        </h3>
        <p>
          ScamShield stores scan history and settings only on this device. When local
          evidence justifies enrichment, only minimal sanitized security signals are
          sent to the ScamShield API — never passwords, cookies, tokens, or full page
          contents.
        </p>
      </section>

      <button
        type="button"
        onClick={onReset}
        className="min-h-[36px] w-full rounded-xl border border-red-500/25 bg-white py-2 text-xs font-bold text-red-600 shadow-sm transition-colors hover:bg-red-500/[0.06] dark:bg-white/5 dark:text-red-400"
      >
        Reset settings
      </button>
    </div>
  );
}
