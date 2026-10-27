import { describe, expect, it } from "vitest";
import { detect } from "../src/detect.js";
import { MAX_INPUT_BYTES, scan } from "../src/index.js";
import { getRules } from "../src/rules/index.js";
import { ALNUM, B64, rand } from "./helpers.js";

const LIMIT_MS = 2000;
const PRINTABLE = " \n\t" + ALNUM + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/** On failure, name the slowest rules so they can be fixed or excluded. */
function slowestRules(text: string): string {
  const times = getRules().rules.map((r) => {
    const t = performance.now();
    detect(text, new Set([r.id]));
    return [performance.now() - t, r.id] as const;
  });
  return times
    .sort((a, b) => b[0] - a[0])
    .slice(0, 5)
    .map(([t, id]) => `${id}: ${t.toFixed(0)}ms`)
    .join(", ");
}

describe("performance on 1 MiB input", () => {
  getRules(); // compile outside the timing

  for (const [name, alphabet] of [
    ["random printable text", PRINTABLE],
    ["base64", B64],
    ["key=value lines", "key=abcdef0123456789\n"],
  ] as const) {
    it(name, () => {
      const text = alphabet.length > 30 ? rand(alphabet, MAX_INPUT_BYTES) : alphabet.repeat(MAX_INPUT_BYTES / alphabet.length);
      const t = performance.now();
      scan(text);
      const ms = performance.now() - t;
      if (ms > LIMIT_MS) expect.fail(`${name}: ${ms.toFixed(0)}ms > ${LIMIT_MS}ms; slowest rules: ${slowestRules(text)}`);
    });
  }
});
