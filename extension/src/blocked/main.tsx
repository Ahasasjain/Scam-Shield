import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BlockedPage } from "@/components/Blocked";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import type { RiskVerdict } from "@shared/index";

const container = document.getElementById("root");
if (!container) throw new Error("Blocked page root element missing");

document.body.dataset.surface = "blocked";

const params = new URLSearchParams(window.location.search);
const url = params.get("url") ?? "";
const rawVerdict = params.get("verdict");
const verdict: RiskVerdict =
  rawVerdict === "DANGEROUS" ||
  rawVerdict === "HIGH_RISK" ||
  rawVerdict === "SUSPICIOUS"
    ? rawVerdict
    : "DANGEROUS";

function goBack(): void {
  // NEVER use history.back() here. blocked.html was loaded via
  // chrome.tabs.update on top of the dangerous page, so history is
  // [..., dangerousUrl, blocked.html] — back() lands straight back on the
  // same dangerous website the user just escaped. Instead navigate the tab
  // to a guaranteed-safe page.
  void (async () => {
    try {
      const tab = await chrome.tabs.getCurrent();
      if (typeof tab?.id === "number") {
        try {
          await chrome.tabs.update(tab.id, { url: "chrome://newtab/" });
          return;
        } catch {
          try {
            await chrome.tabs.update(tab.id, { url: "about:blank" });
            return;
          } catch {
            // Fall through to location.href below.
          }
        }
      }
    } catch {
      // Fall through to location.href below.
    }
    try {
      window.location.href = "about:blank";
    } catch {
      // Nowhere safe to go — stay on the block page (still safer than the
      // dangerous site).
    }
  })();
}

function continueAnyway(): void {
  // Only ever navigate back to a real website — never javascript: or data:.
  if (!/^https?:\/\//i.test(url)) {
    goBack();
    return;
  }
  // Record the bypass BEFORE navigating back: the return navigation would
  // otherwise re-trigger the block and trap the user in a loop. The worker
  // can be unreachable (MV3 naps), in which case the callback never fires —
  // so navigate anyway after a short timeout rather than stranding the user.
  let done = false;
  const go = () => {
    if (done) return;
    done = true;
    window.location.href = url;
  };
  try {
    chrome.runtime.sendMessage({ type: "BYPASS_BLOCK", url }, () => {
      void chrome.runtime.lastError;
      go();
    });
  } catch {
    go();
    return;
  }
  setTimeout(go, 1500);
}

createRoot(container).render(
  <StrictMode>
    <ErrorBoundary>
      <BlockedPage url={url} verdict={verdict} onGoBack={goBack} onContinue={continueAnyway} />
    </ErrorBoundary>
  </StrictMode>,
);
