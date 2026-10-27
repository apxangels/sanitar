import { describe, expect, it } from "vitest";
import { compileUserRules, sanitize, scan, USER_RULE_ID } from "../src/index.js";
import { fake } from "./helpers.js";

describe("user rules (extraRules)", () => {
  it("replaces what built-in rules don't catch", () => {
    const text = "contact: ivan@corp.example, order 44324";
    // pii off: the built-in email rule would catch it otherwise
    expect(sanitize(text, { mode: "placeholder", pii: false }).text).toBe(text);
    const r = sanitize(text, { mode: "placeholder", pii: false, extraRules: ["[\\w.]+@corp\\.example"] });
    expect(r.text).toBe("contact: <secret>, order 44324");
    expect(r.findings).toEqual([
      expect.objectContaining({ ruleId: USER_RULE_ID, category: "secret", start: 9, end: 26, line: 1 }),
    ]);
    expect(r.ruleErrors).toEqual([]);
  });

  it("replaces only the first capture group when there is one", () => {
    const r = sanitize("ticket=SEC-1234 ok", { mode: "placeholder", extraRules: ["ticket=(SEC-\\d+)"] });
    expect(r.text).toBe("ticket=<secret> ok");
  });

  it("works with every mode and the typed placeholder", () => {
    const opts = { extraRules: ["INTERNAL-\\d+"] };
    expect(sanitize("id INTERNAL-42", { mode: "erase", ...opts }).text).toBe("id ");
    expect(sanitize("id INTERNAL-42", { mode: "placeholder", placeholderWithType: true, ...opts }).text).toBe(
      "id <secret:user-rule>",
    );
    expect(sanitize("id INTERNAL-42", { mode: "random", ...opts }).text).toMatch(/^id [A-Z]{8}-\d{2}$/);
  });

  it("all matches, several lines, /pattern/flags", () => {
    const r = sanitize("Foo1 foo2\nFOO3", { mode: "erase", extraRules: ["/foo\\d/i"] });
    expect(r.text).toBe(" \n");
    expect(r.findings.map((f) => f.line)).toEqual([1, 1, 2]);
  });

  it("invalid rules are reported in ruleErrors with line numbers; the valid ones apply", () => {
    const r = sanitize("a SECRETX b", { mode: "erase", extraRules: ["(unclosed", "", "SECRETX"] });
    expect(r.text).toBe("a  b");
    expect(r.ruleErrors).toEqual([expect.objectContaining({ line: 1, pattern: "(unclosed" })]);
    expect(r.errors).toEqual([]); // exclusion errors stay separate
    expect(compileUserRules(["[z-a]"]).errors[0]!.line).toBe(1);
  });

  it("exclusions still apply to user-rule findings", () => {
    const r = sanitize("A-1 A-2", { mode: "erase", extraRules: ["A-\\d"], exclusions: ["^A-2$"] });
    expect(r.text).toBe(" A-2");
    expect(r.excluded.map((f) => f.ruleId)).toEqual([USER_RULE_ID]);
  });

  it("overlapping a built-in finding: one merged region, specific built-in names win over user rules defined later", () => {
    const gh = fake.githubPat();
    const r = sanitize(`t=${gh}`, { mode: "placeholder", placeholderWithType: true, extraRules: ["t=(\\S+)"] });
    expect(r.text).toBe("t=<secret:github-pat>");
  });

  it("empty matches and no rules are harmless", () => {
    expect(sanitize("abc", { mode: "erase", extraRules: ["x*"] }).text).toBe("abc");
    expect(scan("abc", { extraRules: [] }).findings).toEqual([]);
    expect(scan("abc").ruleErrors).toEqual([]);
  });

  it("y flag doesn't anchor matching", () => {
    expect(sanitize("a X1 X2", { mode: "erase", extraRules: ["/X\\d/y"] }).text).toBe("a  ");
  });
});
