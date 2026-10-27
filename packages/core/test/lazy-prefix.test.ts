/**
 * Rules starting with a lazy `[\w.-]{0,N}?` are run without that prefix and the
 * match start is restored by scanning left (see Rule.leftExtend). This checks
 * that the result is identical to running the original regex.
 */
import { describe, expect, it } from "vitest";
import data from "../src/rules/gitleaks.json" with { type: "json" };
import { getRules, splitLazyPrefix } from "../src/rules/index.js";
import { ALNUM, rand } from "./helpers.js";

function originalMatches(source: string, flags: string, text: string): string[] {
  return [...text.matchAll(new RegExp(source, flags + "g"))].map((m) => `${m.index}:${m[0]}`);
}

function optimizedMatches(source: string, flags: string, n: number, text: string): string[] {
  const out: string[] = [];
  let prevEnd = 0;
  for (const m of text.matchAll(new RegExp(splitLazyPrefix(source).source, flags + "g"))) {
    let s = m.index!;
    const e = s + m[0].length;
    const limit = Math.max(prevEnd, s - n);
    while (s > limit && /[\w.-]/.test(text[s - 1]!)) s--;
    prevEnd = e;
    out.push(`${s}:${text.slice(s, e)}`);
  }
  return out;
}

describe("lazy prefix optimisation", () => {
  const rules = data.rules.filter((r) => splitLazyPrefix(r.regex).leftExtend !== undefined);

  it("applies to the keyword=value rules", () => {
    expect(rules.length).toBeGreaterThan(50);
    expect(getRules().rules.filter((r) => r.leftExtend).length).toBe(rules.length);
  });

  it("gives the same matches as the original regex", () => {
    for (const r of rules) {
      const kw = r.keywords[0] ?? "key";
      const pieces: string[] = [];
      for (let i = 0; i < 20; i++) {
        const ident = rand(ALNUM + "_.-", i * 4) + kw + rand(ALNUM + "_", i % 3);
        const sep = [" = ", ":", '="', " => ", "="][i % 5]!;
        pieces.push(`${ident}${sep}${rand(ALNUM + "-_", 8 + i * 4)}${i % 2 ? '"' : ""}`);
      }
      const text = pieces.join(i2sep());
      const n = splitLazyPrefix(r.regex).leftExtend!;
      expect(optimizedMatches(r.regex, r.flags, n, text), r.id).toEqual(originalMatches(r.regex, r.flags, text));
    }
  });
});

function i2sep(): string {
  return ["\n", " ", "; ", "\t"][Math.floor(Math.random() * 4)]!;
}
