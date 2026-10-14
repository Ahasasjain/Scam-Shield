import { useCallback, useEffect, useState } from "react";
import type { ExtensionSettings, HistoryEntry, ThemeSetting } from "@shared/index";
import { getSettings as fetchSettings } from "@/services/api/securityApi";
import {
  clearHistory,
  getHistory,
  getSettings as readLocalSettings,
  saveSettings,
} from "@/utils/storage";

/** Loads settings once and exposes an update function. */
export function useSettings(): {
  settings: ExtensionSettings | null;
  update: (patch: Partial<ExtensionSettings>) => Promise<void>;
  reload: () => Promise<void>;
} {
  const [settings, setSettings] = useState<ExtensionSettings | null>(null);

  const reload = useCallback(async () => {
    // The background worker is the primary source, but it may be unreachable
    // (worker killed, context invalidated). Fall back to a direct local read —
    // it is the same backing store — so the settings tab never stays blank.
    try {
      const response = await fetchSettings();
      if (response.ok) {
        setSettings(response.data);
        return;
      }
    } catch {
      // Fall through to the local read below.
    }
    try {
      setSettings(await readLocalSettings());
    } catch {
      // Keep the previous settings on screen rather than blanking the UI.
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const update = useCallback(async (patch: Partial<ExtensionSettings>) => {
    try {
      setSettings(await saveSettings(patch));
    } catch {
      // Callers already guard with try/catch; the hook keeps the last known
      // settings rather than surfacing a storage failure as a crash.
    }
  }, []);

  return { settings, update, reload };
}

export function useHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const refresh = useCallback(async () => {
    try {
      setHistory(await getHistory());
    } catch {
      // Keep the previous list rather than blanking on a storage failure.
    }
  }, []);

  const clear = useCallback(async () => {
    try {
      await clearHistory();
      setHistory([]);
    } catch {
      // Keep the visible list if the clear failed.
    }
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
