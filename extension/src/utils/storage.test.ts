import { beforeEach, describe, expect, it } from "vitest";
import {
  addHistoryEntry,
  clearHistory,
  getHistory,
  getSettings,
  resetSettings,
  saveSettings,
} from "@/utils/storage";
import { mockChrome } from "../../tests/mocks/chrome";

describe("storage utils", () => {
  beforeEach(() => {
    mockChrome.storage.local.get.mockClear();
    mockChrome.storage.local.set.mockClear();
  });

  it("returns default settings when nothing stored", async () => {
    const settings = await getSettings();
    expect(settings).toEqual({
      aiEnabled: false, // spec §7: AI default OFF
      autoScan: true, // user request: automatic scanning ON by default
      theme: "system",
    });
  });

  it("saves and reads back settings", async () => {
    await saveSettings({ aiEnabled: true });
    const settings = await getSettings();
    expect(settings.aiEnabled).toBe(true);
  });

  it("ignores corrupt stored settings", async () => {
    mockChrome.storage.local.get.mockResolvedValueOnce({
      settings: { aiEnabled: "yes", theme: "rainbow" },
    });
    const settings = await getSettings();
    expect(settings.aiEnabled).toBe(false);
    expect(settings.theme).toBe("system");
  });

  it("resets to defaults", async () => {
    await saveSettings({ aiEnabled: true, theme: "dark" });
    const after = await resetSettings();
    expect(after.aiEnabled).toBe(false);
    expect(after.theme).toBe("system");
  });

  it("caps history at 50 entries with newest first", async () => {
    for (let i = 0; i < 55; i++) {
      await addHistoryEntry({
        hostname: `site-${i}.com`,
        score: 90,
        riskLevel: "safe",
        scannedAt: i,
      });
    }
    const history = await getHistory();
    expect(history).toHaveLength(50);
    expect(history[0]?.hostname).toBe("site-54.com");
  });

  it("clears history", async () => {
    await addHistoryEntry({
      hostname: "a.com",
      score: 50,
      riskLevel: "medium",
      scannedAt: 1,
    });
    await clearHistory();
    expect(await getHistory()).toHaveLength(0);
  });
});
