import { useCallback, useEffect, useState } from "react";
import type { ExtensionSettings, HistoryEntry, ThemeSetting } from "@shared/index";
import { getSettings as fetchSettings } from "@/services/api/securityApi";
import { getHistory, saveSettings, clearHistory } from "@/utils/storage";

/** Loads settings once and exposes an update function. */
export function useSettings(): {
  settings: ExtensionSettings | null;
  update: (patch: Partial<ExtensionSettings>) => Promise<void>;
  reload: () => Promise<void>;
} {
  const [settings, setSettings] = useState<ExtensionSettings | null>(null);

  const reload = useCallback(async () => {
    const response = await fetchSettings();
    if (response.ok) setSettings(response.data);
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const update = useCallback(async (patch: Partial<ExtensionSettings>) => {
    setSettings(await saveSettings(patch));
  }, []);

  return { settings, update, reload };
}

export function useHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const refresh = useCallback(async () => {
    setHistory(await getHistory());
  }, []);

  const clear = useCallback(async () => {
    await clearHistory();
    setHistory([]);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { history, refresh, clear };
}

/** Applies the theme setting to the document root (light/dark/system). */
export function useTheme(theme: ThemeSetting | undefined): void {
  useEffect(() => {
    if (!theme) return;
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");

    const apply = () => {
      const dark = theme === "dark" || (theme === "system" && media.matches);
      root.classList.toggle("dark", dark);
    };

    apply();
    if (theme === "system") {
      media.addEventListener("change", apply);
      return () => media.removeEventListener("change", apply);
    }
  }, [theme]);
}
