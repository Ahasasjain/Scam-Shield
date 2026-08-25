import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/components/App";

const container = document.getElementById("root");
if (!container) throw new Error("Side panel root element missing");

// The background worker opens the side panel with ?warning=1 when an
// auto-scan produces a low score — pass that through so the app can
// surface the warning immediately.
const params = new URLSearchParams(window.location.search);
const autoWarning = params.get("warning") === "1";

createRoot(container).render(
  <StrictMode>
    <App variant="sidepanel" autoWarning={autoWarning} />
  </StrictMode>,
);
