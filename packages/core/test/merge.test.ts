import { describe, expect, it } from "vitest";
import type { RawFinding } from "../src/detect.js";
import { mergeOverlaps, randomLike, typedPlaceholder, withoutOverlaps } from "../src/replace.js";
import { Specificity, type Rule } from "../src/rules/index.js";

function rule(id: string, specificity: Specificity): Rule {
  return {
    id,
    description: id,
    regex: /x/gd,
    secretGroup: 0,
    entropy: 0,
    keywords: [],
    allowlists: [],
    specificity,
    prefixes: [],
    requireDigit: false,
  };
}
const generic = rule("generic-api-key", Specificity.Generic);
const contextual = rule("authorization-header", Specificity.Contextual);
const specific = rule("github-pat", Specificity.Specific);
const f = (r: Rule, start: number, end: number, ruleIndex = 0): RawFinding => ({ rule: r, ruleIndex, start, end });

describe("mergeOverlaps", () => {
  it("keeps disjoint and adjacent findings separate", () => {
    const out = mergeOverlaps([f(specific, 10, 20), f(generic, 0, 5), f(generic, 5, 10)]);
    expect(out.map((r) => [r.start, r.end])).toEqual([[0, 5], [5, 10], [10, 20]]);
  });

  it("merges a partial overlap into the union, generic loses", () => {
    const out = mergeOverlaps([f(generic, 0, 15), f(specific, 10, 30)]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ start: 0, end: 30, rule: specific });
  });

  it("merges chains of overlaps", () => {
    const out = mergeOverlaps([f(generic, 0, 10), f(contextual, 8, 20), f(generic, 19, 25)]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ start: 0, end: 25, rule: contextual });
  });

  it("same specificity: longer match wins, then the rule defined first", () => {
    const other = rule("other", Specificity.Specific);
    expect(mergeOverlaps([f(specific, 0, 10, 1), f(other, 2, 20, 2)])[0]!.rule).toBe(other);
    expect(mergeOverlaps([f(specific, 0, 10, 5), f(other, 0, 10, 2)])[0]!.rule).toBe(other);
  });

  it("withoutOverlaps drops regions touching kept ones", () => {
    const kept = mergeOverlaps([f(specific, 10, 20), f(specific, 40, 50)]);
    const ex = mergeOverlaps([f(generic, 0, 5), f(generic, 15, 25), f(generic, 30, 40), f(generic, 49, 60)]);
    expect(withoutOverlaps(ex, kept).map((r) => r.start)).toEqual([0, 30]);
  });
});

describe("replacement helpers", () => {
  it("typedPlaceholder", () => {
    expect(typedPlaceholder("<secret>", "jwt")).toBe("<secret:jwt>");
    expect(typedPlaceholder("REDACTED", "jwt")).toBe("REDACTED:jwt");
    expect(typedPlaceholder("{{x}}", "jwt")).toBe("{{x:jwt}}");
  });

  it("randomLike handles long secrets (getRandomValues 64 KiB limit)", () => {
    const s = "a".repeat(200_000);
    const out = randomLike(s, { prefixes: [] });
    expect(out).toHaveLength(s.length);
    expect(out).toMatch(/^[a-z]+$/);
  });

  it("randomLike does not keep a prefix that is most of the secret", () => {
    expect(randomLike("abcd1", { prefixes: ["abcd"] }).startsWith("abcd")).toBe(false);
    expect(randomLike("abcd12345", { prefixes: ["abcd"] }).startsWith("abcd")).toBe(true);
  });

  it("randomLike keeps non-alphanumerics", () => {
    const out = randomLike("ab-cd_ef/gh+ij=kl.mn", { prefixes: [] });
    expect(out.replace(/[a-z]/g, "")).toBe("-_/+=.");
  });
});
