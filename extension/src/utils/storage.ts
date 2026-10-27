import {
  DEFAULT_SETTINGS,
  HISTORY_LIMIT,
  type ExtensionSettings,
  type HistoryEntry,
} from "@shared/index";

/**
 * Typed wrapper around chrome.storage.local (spec §7, §24, §25).
 * All reads are migration-safe: unknown/missing fields fall back to defaults.
 */

const SETTINGS_KEY = "settings";
const SETTINGS_VERSION_KEY = "settingsVersion";
const HISTORY_KEY = "scanHistory";
const AI_BASE_URL_KEY = "aiBaseUrl";

/**
 * Bump when DEFAULT_SETTINGS semantics change. v2 introduced autoScan=true;
 * users with v1-stored settings get the new default applied once.
 */
const CURRENT_SETTINGS_VERSION = 2;

function storage(): chrome.storage.StorageArea {
  return chrome.storage.local;
}

export async function getSettings(): Promise<ExtensionSettings> {
  const result = await storage().get([SETTINGS_KEY, SETTINGS_VERSION_KEY]);
  const stored = result[SETTINGS_KEY];
  const storedVersion =
    typeof result[SETTINGS_VERSION_KEY] === "number"
      ? (result[SETTINGS_VERSION_KEY] as number)
      : 1;

  if (typeof stored !== "object" || stored === null) {
    return { ...DEFAULT_SETTINGS };
  }
  const raw = stored as Record<string, unknown>;

  // Migration: v1 stored autoScan=false as an explicit user choice even
  // though it was merely the old default. v2 applies the new default once
  // to profiles that never made an explicit choice under v2 or later.
  const autoScanDefault = DEFAULT_SETTINGS.autoScan;

  return {
    autoScan:
      typeof raw["autoScan"] === "boolean" && storedVersion >= CURRENT_SETTINGS_VERSION
        ? raw["autoScan"]
        : autoScanDefault,
    theme:
      raw["theme"] === "light" || raw["theme"] === "dark" || raw["theme"] === "system"
        ? raw["theme"]
        : DEFAULT_SETTINGS.theme,
  };
}

export async function saveSettings(
  patch: Partial<ExtensionSettings>,
): Promise<ExtensionSettings> {
  const current = await getSettings();
  const next: ExtensionSettings = { ...current, ...patch };
  await storage().set({
    [SETTINGS_KEY]: next,
    [SETTINGS_VERSION_KEY]: CURRENT_SETTINGS_VERSION,
  });
  return next;
}

export async function resetSettings(): Promise<ExtensionSettings> {
  // The version key must be written too: without it the next getSettings()
  // believes the profile predates v2 and re-applies the migration path.
  await storage().set({
    [SETTINGS_KEY]: { ...DEFAULT_SETTINGS },
    [SETTINGS_VERSION_KEY]: CURRENT_SETTINGS_VERSION,
  });
  return { ...DEFAULT_SETTINGS };
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length <= maxLength;
}

export async function getHistory(): Promise<HistoryEntry[]> {
  const result = await storage().get(HISTORY_KEY);
  const stored = result[HISTORY_KEY];
  if (!Array.isArray(stored)) return [];
  // Corrupt entries (extension bug, failed migration, edited storage) must
  // never reach the timeline: unbounded strings bloat the popup and NaN
  // scores break sorting and display.
  return stored.filter((entry): entry is HistoryEntry => {
    if (typeof entry !== "object" || entry === null) return false;
    const candidate = entry as Record<string, unknown>;
    return (
      (typeof candidate["url"] === "undefined" ||
        isBoundedString(candidate["url"], 2000)) &&
      isBoundedString(candidate["hostname"], 253) &&
      isFiniteNumber(candidate["score"]) &&
      isFiniteNumber(candidate["scannedAt"])
    );
  });
}

export async function addHistoryEntry(entry: HistoryEntry): Promise<void> {
  const history = await getHistory();
  const next = [entry, ...history].slice(0, HISTORY_LIMIT);
  await storage().set({ [HISTORY_KEY]: next });
}

export async function clearHistory(): Promise<void> {
  await storage().set({ [HISTORY_KEY]: [] });
}

/**
 * Backend base URL for AI/threat analysis.
 *
 * The build-time URL always wins so an old `aiBaseUrl` value left in
 * chrome.storage by a previous build cannot silently point the extension back
 * at localhost. The stored value is only a fallback for builds that were made
 * without a baked URL at all.
 */
export async function getAiBaseUrl(): Promise<string> {
  const baked =
    typeof __SCAMSHIELD_API_URL__ === "string" ? __SCAMSHIELD_API_URL__ : "";
  if (baked !== "") return baked;

  const result = await storage().get(AI_BASE_URL_KEY);
  const value = result[AI_BASE_URL_KEY];
  return typeof value === "string" ? value : "";
}

export async function setAiBaseUrl(url: string): Promise<void> {
  await storage().set({ [AI_BASE_URL_KEY]: url });
}
