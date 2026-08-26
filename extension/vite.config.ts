import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import type { Plugin } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));

/**
 * Moves the built HTML entries to the dist root with the exact names the
 * manifest expects (popup.html / sidepanel.html) and rewrites asset paths.
 */
function flattenExtensionHtml(): Plugin {
  return {
    name: "flatten-extension-html",
    closeBundle() {
      const outDir = resolve(root, "dist");
      const moves: Array<[string, string]> = [
        ["src/popup/index.html", "popup.html"],
        ["src/sidepanel/index.html", "sidepanel.html"],
      ];
      let moved = false;
      for (const [from, to] of moves) {
        const src = resolve(outDir, from);
        if (fs.existsSync(src)) {
          let html = fs.readFileSync(src, "utf8");
          // Rewrite relative asset refs to be root-relative for the extension.
          html = html.replaceAll(/(src|href)="(\.\.\/)+/g, "$1=");
          fs.writeFileSync(resolve(outDir, to), html);
          moved = true;
        }
      }
      if (moved) {
        fs.rmSync(resolve(outDir, "src"), { recursive: true, force: true });
      }
    },
  };
}

/**
 * Multi-entry Vite build for Manifest V3:
 * - popup.html / sidepanel.html  → React UIs
 * - background                   → service worker (ES module)
 * - content                      → on-demand content script (IIFE, no imports)
 */
export default defineConfig(() => ({
  plugins: [react(), tailwindcss(), flattenExtensionHtml()],
  define: {
    // Baked at build time — end users never configure an API endpoint.
    // Set SCAMSHIELD_API_URL when building for production.
    __SCAMSHIELD_API_URL__: JSON.stringify(
      process.env.SCAMSHIELD_API_URL ?? "",
    ),
  },
  resolve: {
    alias: {
      "@shared": resolve(root, "../shared/src"),
      "@": resolve(root, "src"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    target: "chrome120",
    rollupOptions: {
      input: {
        popup: resolve(root, "src/popup/index.html"),
        sidepanel: resolve(root, "src/sidepanel/index.html"),
        background: resolve(root, "src/background/index.ts"),
        content: resolve(root, "src/content/index.ts"),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === "background" || chunk.name === "content"
            ? "[name].js"
            : "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
        // Content scripts must be a single self-contained IIFE.
        format: "es",
        manualChunks(id) {
          if (id.includes("src/content/")) return "content";
          return undefined;
        },
      },
    },
  },
}));
