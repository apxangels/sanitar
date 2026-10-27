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
/** personal data in the fixture: the commit author's email (a true positive) */
const PII_BASELINE = 1;

const text = readFileSync(join(import.meta.dirname, "fixtures", "benign.md"), "utf8");
const report = (pii: boolean) =>
  scan(text, { pii })
    .findings.filter((f) => pii === (f.category === "pii"))
    .map((f) => `${f.ruleId} @ line ${f.line}: ${JSON.stringify(text.slice(f.start, f.end))}`);

describe("false positives", () => {
  it(`benign text has at most ${BASELINE} secret findings`, () => {
    const r = report(false);
    expect(r.length, r.join("\n")).toBeLessThanOrEqual(BASELINE);
  });

  it(`benign text has at most ${PII_BASELINE} personal-data findings`, () => {
    const r = report(true);
    expect(r.length, r.join("\n")).toBeLessThanOrEqual(PII_BASELINE);
  });
});
