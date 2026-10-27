/**
 * core must run unchanged in a browser, Node and an MV3 service worker.
 * tsconfig already compiles it with lib ES2023 only (no DOM, no Node types);
 * this test additionally greps for environment-specific globals.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(import.meta.dirname, "..", "src");
// usages like `process.env`, `window[...]`, `require(` — not mere mentions inside regex literals
const FORBIDDEN =
  /\b(?:window|document|navigator|localStorage|sessionStorage|process|Buffer|console|self)\s*[.[]|\brequire\s*\(|\b__dirname\b|from\s+["']node:|import\(\s*["']node:/;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : p.endsWith(".ts") ? [p] : [];
  });
}

describe("core portability", () => {
  it("uses no DOM/Node globals and no console", () => {
    for (const file of files(SRC)) {
      const code = readFileSync(file, "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      const m = FORBIDDEN.exec(code);
      expect(m?.[0], file).toBeUndefined();
    }
  });

  it("has no runtime dependencies", () => {
    const pkg = JSON.parse(readFileSync(join(SRC, "..", "package.json"), "utf8")) as Record<string, unknown>;
    expect(pkg.dependencies ?? {}).toEqual({});
  });
});
