import { logger } from "../lib/logger.js";

/**
 * OpenPhish feed integration (free community feed).
 *
 * Downloads https://openphish.com/feed.txt (one URL per line) on an interval
 * and serves lookups from memory. URLs are stored both full (host+path) and
 * by registrable host so a navigation to any path on a known-bad host matches.
 *
 * Licensing: OpenPhish Community Feed is free for non-commercial use.
 * For commercial deployment, obtain an OpenPhish Premium license or swap in
 * another provider — this module is the single integration point.
 */

const DEFAULT_FEED_URL = "https://openphish.com/feed.txt";
const REFRESH_INTERVAL_MS = 30 * 60 * 1000; // 30 min
const MAX_FEED_ENTRIES = 500_000;

interface FeedData {
  /** Full URLs as published: https://bad.example/path */
  urls: Set<string>;
  /** Hostnames extracted from feed entries (any path on them is suspect). */
  hosts: Set<string>;
  lastUpdated: number;
  entryCount: number;
}

let feed: FeedData = {
  urls: new Set(),
  hosts: new Set(),
  lastUpdated: 0,
  entryCount: 0,
};
let refreshTimer: NodeJS.Timeout | null = null;

export function getFeed(): FeedData {
  return feed;
}

export async function refreshFeed(feedUrl?: string): Promise<boolean> {
  const url = feedUrl ?? process.env["THREAT_FEED_URL"] ?? DEFAULT_FEED_URL;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30_000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!response.ok) {
      logger.warn({ status: response.status }, "threat feed download failed");
      return false;
    }
    const text = await response.text();
    const urls = new Set<string>();
    const hosts = new Set<string>();

    for (const line of text.split("\n")) {
      const entry = line.trim();
      if (!entry || entry.startsWith("#")) continue;
      if (urls.size >= MAX_FEED_ENTRIES) break;
      urls.add(entry);
      try {
        hosts.add(new URL(entry).hostname.toLowerCase());
      } catch {
        // malformed line — skip
      }
    }

    feed = { urls, hosts, lastUpdated: Date.now(), entryCount: urls.size };
    logger.info({ entries: feed.entryCount }, "threat feed refreshed");
    return true;
  } catch (error) {
    logger.warn({ error }, "threat feed refresh failed");
    return false;
  }
}

export function startFeedRefresh(): void {
  // Initial load (non-blocking so server starts immediately).
  void refreshFeed();
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => void refreshFeed(), REFRESH_INTERVAL_MS);
}

export function stopFeedRefresh(): void {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
}

export interface FeedLookupResult {
  matched: boolean;
  threatType?: string;
  confidence: "confirmed" | "high" | "medium";
}

/** Exact URL match → confirmed; same host → high. */
export function lookupFeed(url: string): FeedLookupResult | null {
  if (feed.urls.size === 0) return null; // feed not loaded yet
  const normalized = url.toLowerCase();

  if (feed.urls.has(normalized)) {
    return { matched: true, threatType: "phishing", confidence: "confirmed" };
  }

  try {
    const host = new URL(normalized).hostname.toLowerCase();
    if (feed.hosts.has(host)) {
      return { matched: true, threatType: "phishing", confidence: "high" };
    }
  } catch {
    // fall through
  }
  return null;
}
