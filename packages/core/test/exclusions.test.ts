import { describe, expect, it } from "vitest";
import { compileExclusions } from "../src/exclusions.js";
import { sanitize } from "../src/index.js";
import { fake } from "./helpers.js";

describe("exclusions", () => {
  it("excluded secrets stay in the text and are reported separately", () => {
    const gh = fake.githubPat();
    const aws = fake.awsKeyId();
    const r = sanitize(`a=${gh}\nb=${aws}\n`, { mode: "placeholder", exclusions: ["^gh" + "p_"] });
    expect(r.text).toBe(`a=${gh}\nb=<secret>\n`);
    expect(r.findings.map((f) => f.ruleId)).toEqual(["aws-access-token"]);
    expect(r.excluded.map((f) => f.ruleId)).toEqual(["github-pat"]);
    expect(r.errors).toEqual([]);
  });

  it("matches with test(), not a full match", () => {
    const gh = fake.githubPat();
    const r = sanitize(`a=${gh}`, { mode: "erase", exclusions: [gh.slice(5, 12)] });
    expect(r.text).toBe(`a=${gh}`);
  });

  it("an invalid regex is reported with its line number, the others still apply", () => {
    const gh = fake.githubPat();
    const r = sanitize(`a=${gh}`, { mode: "erase", exclusions: ["(unclosed", "", "^gh" + "p_", "[z-a]"] });
    expect(r.text).toBe(`a=${gh}`);
    expect(r.errors.map((e) => e.line)).toEqual([1, 4]);
    expect(r.errors[0]!.pattern).toBe("(unclosed");
    expect(r.errors[0]!.message).toMatch(/Invalid regular expression/);
  });

  it("supports /pattern/flags", () => {
    const gh = fake.githubPat();
    expect(sanitize(`a=${gh}`, { mode: "erase", exclusions: ["/^GH" + "P_/i"] }).text).toBe(`a=${gh}`);
    expect(sanitize(`a=${gh}`, { mode: "erase", exclusions: ["^GH" + "P_"] }).text).toBe("a=");
  });

  it("g/y flags don't make matching stateful", () => {
    const a = fake.githubPat();
    const b = fake.githubPat();
    const r = sanitize(`${a}\n${b}`, { mode: "erase", exclusions: ["/^gh" + "p_/g"] });
    expect(r.excluded).toHaveLength(2);
  });

  it("a path is not mistaken for /pattern/flags", () => {
    const ex = compileExclusions(["/usr/bin"]);
    expect(ex.errors).toEqual([]);
    expect(ex.regexes[0]!.source).toBe("\\/usr\\/bin");
  });
});
