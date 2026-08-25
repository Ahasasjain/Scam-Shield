import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/components/App";

const container = document.getElementById("root");
if (!container) throw new Error("Popup root element missing");

createRoot(container).render(
  <StrictMode>
    <App variant="popup" />
  </StrictMode>,
);
