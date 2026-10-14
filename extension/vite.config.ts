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
 * Wraps the built content script in an IIFE.
 *
 * `output.format` is "es" because the background service worker is a module.
 * That format does NOT scope a content script's top-level `const`/`let`, so
 * every re-injection into the same document re-declared the same identifiers
 * and threw `SyntaxError: Identifier 'w' has already been declared`, killing
 * the whole script (page signals stopped working entirely).
 *
 * The background re-injects `content.js` on every scan, and scans fire from
 * navigation, tab activation, and SPA route changes — so a single page view
 * can receive this file many times. Wrapping it makes re-injection harmless
 * and enforces what this config's comment always claimed.
 *
 * Safe because the content entry has no importers and nothing reads its
 * exports at runtime.
 */
function wrapContentScriptInIife(): Plugin {
  return {
    name: "wrap-content-script-iife",
    apply: "build",
    generateBundle(_options, bundle) {
      const chunk = bundle["content.js"];
      if (!chunk || chunk.type !== "chunk") return;
      const code = typeof chunk.code === "string" ? chunk.code : "";
      chunk.code = `(function(){\n"use strict";\n${code}\n})();\n`;
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
  plugins: [react(), tailwindcss(), flattenExtensionHtml(), wrapContentScriptInIife()],
  define: {
    // Baked at build time — end users never configure an API endpoint.
    // Set SCAMSHIELD_API_URL when building for production.
    __SCAMSHIELD_API_URL__: JSON.stringify(
      process.env.SCAMSHIELD_API_URL ?? "http://localhost:8787",
    ),
    __SCAMSHIELD_AI_ALWAYS_RUN__: JSON.stringify(
      process.env.SCAMSHIELD_AI_ALWAYS_RUN === "true",
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
