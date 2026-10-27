/**
 * Benign text (git hashes, UUIDs, code, configs with placeholders, markdown).
 * False positives don't have to be zero, but this pins the current number so
 * it can't grow unnoticed. If you lower it — great, update the baseline.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const BASELINE = 0;

describe("false positives", () => {
  it(`benign text has at most ${BASELINE} findings`, () => {
    const text = readFileSync(join(import.meta.dirname, "fixtures", "benign.md"), "utf8");
    const { findings } = scan(text);
    const report = findings.map((f) => `${f.ruleId} @ line ${f.line}: ${JSON.stringify(text.slice(f.start, f.end))}`);
    expect(report.length, report.join("\n")).toBeLessThanOrEqual(BASELINE);
  });
});
