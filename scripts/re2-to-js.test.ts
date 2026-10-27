import { describe, expect, it } from "vitest";
import { convertRe2, Re2ConversionError } from "./lib/re2-to-js.ts";

const js = (p: string) => {
  const r = convertRe2(p);
  return new RegExp(r.source, r.flags);
};

describe("convertRe2", () => {
  it("leading (?i) becomes the i flag", () => {
    expect(convertRe2("(?i)abc")).toEqual({ source: "abc", flags: "i" });
  });

  it("(?i) in the middle only affects the rest of the group", () => {
    const re = js("\\b(p8e-(?i)[a-z0-9]{4})x");
    expect(re.test("p8e-AbC1x")).toBe(true);
    expect(re.test("P8E-abc1x")).toBe(false); // prefix stays case-sensitive
    expect(re.test("p8e-abc1X")).toBe(false); // outside the group
  });

  it("(?-i:...) inside a case-insensitive pattern", () => {
    const re = js("(?i)(?:key|(?-i:[Aa]pi|API))=");
    expect(re.test("KEY=")).toBe(true);
    expect(re.test("Api=")).toBe(true);
    expect(re.test("aPI=")).toBe(false);
  });

  it("(?s:.) matches newlines", () => {
    expect(js("a(?s:.)b").test("a\nb")).toBe(true);
    expect(js("a.b").test("a\nb")).toBe(false);
  });

  it("\\z and POSIX classes", () => {
    expect(js("x\\z").test("x")).toBe(true);
    expect(js("x\\z").test("x\n")).toBe(false);
    expect(js("^[[:alnum:]]+$").test("aZ9")).toBe(true);
    expect(js("^[[:alnum:]]+$").test("a-b")).toBe(false);
  });

  it("']' first in a class is a literal, as in RE2", () => {
    const re = js("^\\[[^]]+]$");
    expect(re.test("[abc]")).toBe(true);
    expect(re.test("[a]c]")).toBe(false);
  });

  it("named groups and literal braces", () => {
    expect(js("(?P<n>a)").exec("a")?.groups?.n).toBe("a");
    expect(js("^\\${(?:\\d+)}$").test("${12}")).toBe(true);
    expect(js("^a{2}$").test("aa")).toBe(true);
  });

  it("refuses what it can't translate", () => {
    expect(() => convertRe2("\\pL")).toThrow(Re2ConversionError);
    expect(() => convertRe2("(?U)a+")).toThrow(Re2ConversionError);
  });
});
