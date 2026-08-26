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
  // though it was merely the old default. v2 applies the new default once.
  const autoScanDefault =
    storedVersion < CURRENT_SETTINGS_VERSION
      ? DEFAULT_SETTINGS.autoScan
      : DEFAULT_SETTINGS.autoScan;

  return {
    aiEnabled:
      typeof raw["aiEnabled"] === "boolean"
        ? raw["aiEnabled"]
        : DEFAULT_SETTINGS.aiEnabled,
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
  await storage().set({ [SETTINGS_KEY]: { ...DEFAULT_SETTINGS } });
  return { ...DEFAULT_SETTINGS };
}

export async function getHistory(): Promise<HistoryEntry[]> {
  const result = await storage().get(HISTORY_KEY);
  const stored = result[HISTORY_KEY];
  if (!Array.isArray(stored)) return [];
  return stored.filter(
    (entry): entry is HistoryEntry =>
      typeof entry === "object" &&
      entry !== null &&
      typeof (entry as HistoryEntry).hostname === "string" &&
      typeof (entry as HistoryEntry).score === "number" &&
      typeof (entry as HistoryEntry).scannedAt === "number",
  );
}

export async function addHistoryEntry(entry: HistoryEntry): Promise<void> {
  const history = await getHistory();
  const next = [entry, ...history].slice(0, HISTORY_LIMIT);
  await storage().set({ [HISTORY_KEY]: next });
}

export async function clearHistory(): Promise<void> {
  await storage().set({ [HISTORY_KEY]: [] });
}

/** Backend base URL for AI/threat analysis. Baked at build time; the
 * stored value (if any) overrides it for development overrides only. */
export async function getAiBaseUrl(): Promise<string> {
  const result = await storage().get(AI_BASE_URL_KEY);
  const value = result[AI_BASE_URL_KEY];
  if (typeof value === "string" && value !== "") return value;
  return typeof __SCAMSHIELD_API_URL__ === "string"
    ? __SCAMSHIELD_API_URL__
    : "";
}

export async function setAiBaseUrl(url: string): Promise<void> {
  await storage().set({ [AI_BASE_URL_KEY]: url });
}
