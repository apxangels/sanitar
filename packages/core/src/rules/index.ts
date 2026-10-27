import gitleaksData from "./gitleaks.json" with { type: "json" };
import { customRules } from "./custom.js";
import { Specificity, type Allowlist, type RegexTarget, type Rule } from "./types.js";

export type { Allowlist, Rule } from "./types.js";
export { Specificity } from "./types.js";

interface JsonRegex {
  source: string;
  flags: string;
}

interface JsonAllowlist {
  condition: string;
  regexTarget: string;
  regexes: JsonRegex[];
  stopwords: string[];
}

interface JsonRule {
  id: string;
  description: string;
  regex: string;
  flags: string;
  secretGroup: number;
  entropy: number;
  keywords: string[];
  allowlists: JsonAllowlist[];
}

interface GitleaksJson {
  gitleaksVersion: string;
  globalAllowlists: JsonAllowlist[];
  rules: JsonRule[];
}

const data = gitleaksData as GitleaksJson;

export const GITLEAKS_VERSION = data.gitleaksVersion;

function compileAllowlist(al: JsonAllowlist): Allowlist {
  return {
    condition: al.condition === "AND" ? "AND" : "OR",
    regexTarget: al.regexTarget as RegexTarget,
    regexes: al.regexes.map((r) => new RegExp(r.source, r.flags)),
    stopwords: al.stopwords,
  };
}

function withGd(re: RegExp): RegExp {
  const flags = new Set(re.flags.split(""));
  flags.add("g");
  flags.add("d");
  return new RegExp(re.source, [...flags].join(""));
}

const LAZY_PREFIX = /^(\(\?:)?\[\\w\\\.\\-\]\{0,(\d+)\}\?/;

/** Splits off a leading lazy `[\w.-]{0,N}?` (see Rule.leftExtend). Exported for tests. */
export function splitLazyPrefix(source: string): { source: string; leftExtend?: number } {
  const m = LAZY_PREFIX.exec(source);
  if (!m) return { source };
  return { source: (m[1] ?? "") + source.slice(m[0].length), leftExtend: Number(m[2]) };
}

let cache: { rules: Rule[]; globalAllowlists: Allowlist[] } | null = null;

/** Compiled rule set. Compiled lazily once and reused. Custom rules come first. */
export function getRules(): { rules: Rule[]; globalAllowlists: Allowlist[] } {
  if (cache) return cache;

  const rules: Rule[] = [];
  for (const def of customRules) {
    rules.push({
      id: def.id,
      description: def.description,
      regex: withGd(def.regex),
      secretGroup: def.secretGroup ?? 0,
      entropy: def.entropy ?? 0,
      keywords: def.keywords.map((k) => k.toLowerCase()),
      allowlists: def.allowlists ?? [],
      specificity: def.specificity,
      prefixes: def.prefixes ?? [],
      ...(def.preserve ? { preserve: def.preserve } : {}),
      requireDigit: false,
    });
  }
  for (const r of data.rules) {
    const generic = r.id.startsWith("generic");
    const split = splitLazyPrefix(r.regex);
    rules.push({
      id: r.id,
      description: r.description,
      regex: new RegExp(split.source, r.flags + "gd"),
      ...(split.leftExtend !== undefined ? { leftExtend: split.leftExtend } : {}),
      secretGroup: r.secretGroup,
      entropy: r.entropy,
      keywords: r.keywords,
      allowlists: r.allowlists.map(compileAllowlist),
      specificity: generic ? Specificity.Generic : Specificity.Specific,
      // gitleaks keywords are usually the token prefix (ghp_, xoxb-, akia…)
      prefixes: generic ? [] : r.keywords,
      requireDigit: generic,
    });
  }
  cache = { rules, globalAllowlists: data.globalAllowlists.map(compileAllowlist) };
  return cache;
}
