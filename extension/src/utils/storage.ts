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
const HISTORY_KEY = "scanHistory";
const AI_BASE_URL_KEY = "aiBaseUrl";

function storage(): chrome.storage.StorageArea {
  return chrome.storage.local;
}

export async function getSettings(): Promise<ExtensionSettings> {
  const result = await storage().get(SETTINGS_KEY);
  const stored = result[SETTINGS_KEY];
  if (typeof stored !== "object" || stored === null) {
    return { ...DEFAULT_SETTINGS };
  }
  const raw = stored as Record<string, unknown>;
  return {
    aiEnabled:
      typeof raw["aiEnabled"] === "boolean"
        ? raw["aiEnabled"]
        : DEFAULT_SETTINGS.aiEnabled,
    autoScan:
      typeof raw["autoScan"] === "boolean"
        ? raw["autoScan"]
        : DEFAULT_SETTINGS.autoScan,
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
  await storage().set({ [SETTINGS_KEY]: next });
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

/** Backend base URL for AI analysis; empty means AI backend not configured. */
export async function getAiBaseUrl(): Promise<string> {
  const result = await storage().get(AI_BASE_URL_KEY);
  const value = result[AI_BASE_URL_KEY];
  return typeof value === "string" ? value : "";
}

export async function setAiBaseUrl(url: string): Promise<void> {
  await storage().set({ [AI_BASE_URL_KEY]: url });
}
