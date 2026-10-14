import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/components/App";
import { ErrorBoundary } from "@/components/ErrorBoundary";

const container = document.getElementById("root");
if (!container) throw new Error("Popup root element missing");

document.body.dataset.surface = "popup";

createRoot(container).render(
  <StrictMode>
    <ErrorBoundary>
      <App variant="popup" />
    </ErrorBoundary>
  </StrictMode>,
);
