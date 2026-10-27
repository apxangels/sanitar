import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

/**
 * CSP as a <meta> tag, for static hosting that can't send headers (GitHub
 * Pages). The Fastify server sends the same policy as a header as well.
 * `connect-src 'none'` makes the browser itself block any fetch/XHR/WebSocket,
 * so the text can't leave the page even by mistake.
 * Build only: the Vite dev server injects inline styles for HMR.
 * (frame-ancestors is ignored in <meta>, so framing can't be blocked on Pages.)
 */
const CSP = [
  "default-src 'self'",
  "connect-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'none'",
].join("; ");

function cspMeta(): Plugin {
  return {
    name: "csp-meta",
    apply: "build",
    transformIndexHtml: () => [
      { tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: CSP }, injectTo: "head-prepend" },
    ],
  };
}

export default defineConfig({
  // relative asset URLs: works both at the server root and under a GitHub Pages subpath (/sanitar/)
  base: "./",
  plugins: [cspMeta()],
  resolve: {
    // use core sources directly: no separate build step in dev, and Vite bundles it anyway
    alias: { "@sanitar/core": fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)) },
  },
  build: {
    target: "es2022",
    // nothing inline: the CSP has no 'unsafe-inline'
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: { port: 5173, strictPort: true },
});
