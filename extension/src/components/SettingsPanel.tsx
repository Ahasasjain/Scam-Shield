import type { ExtensionSettings, ThemeSetting } from "@shared/index";
import { AIModeToggle } from "./AIModeToggle";

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
      <AIModeToggle
        enabled={settings.aiEnabled}
        onChange={(enabled) => onUpdate({ aiEnabled: enabled })}
      />

      <label className="flex items-center justify-between rounded-xl border border-neutral-200 bg-white px-3 py-2.5 dark:border-neutral-800 dark:bg-neutral-900">
        <span>
          <span className="block text-sm font-medium text-neutral-900 dark:text-neutral-100">
            Automatic scanning
          </span>
          <span className="text-[11px] text-neutral-500 dark:text-neutral-400">
            Scan pages automatically as you browse
          </span>
        </span>
        <input
          type="checkbox"
          checked={settings.autoScan}
          onChange={(e) => onUpdate({ autoScan: e.target.checked })}
          className="h-4 w-4 accent-emerald-600"
        />
      </label>

      <div className="rounded-xl border border-neutral-200 bg-white px-3 py-2.5 dark:border-neutral-800 dark:bg-neutral-900">
        <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">
          Theme
        </p>
        <div
          role="radiogroup"
          aria-label="Theme"
          className="mt-2 grid grid-cols-3 gap-1.5"
        >
          {THEMES.map((theme) => (
            <button
              key={theme}
              type="button"
              role="radio"
              aria-checked={settings.theme === theme}
              onClick={() => onUpdate({ theme })}
              className={`rounded-lg px-2 py-1.5 text-xs font-medium capitalize transition-colors ${
                settings.theme === theme
                  ? "bg-shield-600 text-white"
                  : "bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:bg-neutral-800 dark:text-neutral-300 dark:hover:bg-neutral-700"
              }`}
            >
              {theme}
            </button>
          ))}
        </div>
      </div>

      {settings.aiEnabled && (
        <div className="rounded-xl border border-violet-200 bg-violet-50/60 px-3 py-2.5 text-[11px] leading-relaxed text-violet-800 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300">
          AI analysis runs through the official ScamShield API. Only minimal security
          signals are sent — never page contents or credentials.
        </div>
      )}

      <section className="rounded-xl border border-neutral-200 bg-white p-3 text-xs leading-relaxed text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-400">
        <h3 className="mb-1 text-sm font-medium text-neutral-900 dark:text-neutral-100">
          Privacy
        </h3>
        <p>
          ScamShield stores scan history and settings only on this device. With AI off,
          nothing leaves your browser except the threat-feed check (only the site's
          domain is queried). With AI on, only minimal security signals (URL structure,
          page signal counts) are sent to the ScamShield API — never passwords, cookies,
          tokens, or full page contents.
        </p>
      </section>

      <button
        type="button"
        onClick={onReset}
        className="w-full rounded-xl border border-red-200 bg-white py-2 text-xs font-semibold text-red-600 transition-colors hover:bg-red-50 dark:border-red-900 dark:bg-neutral-900 dark:text-red-400 dark:hover:bg-red-950/40"
      >
        Reset settings
      </button>
    </div>
  );
}
