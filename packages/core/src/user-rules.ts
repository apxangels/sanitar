import { parseUserPattern } from "./exclusions.js";
import { Specificity, type Rule } from "./rules/index.js";
import type { ExclusionError } from "./types.js";

/** rule id of every user-defined rule (shown as the finding type, e.g. "<secret:user-rule>") */
export const USER_RULE_ID = "user-rule";

export interface CompiledUserRules {
  rules: Rule[];
  errors: ExclusionError[];
}

/**
 * Compiles user-defined detection rules: extra things to replace that the
 * built-in rules don't catch. Same line format as exclusions: a regex source
 * or "/pattern/flags", one per entry; empty entries are ignored, invalid ones
 * are reported with their 1-based line and skipped.
 *
 * The replaced part is the first non-empty capture group, or the whole match
 * (gitleaks semantics), so `token=(\d+)` replaces only the digits.
 * User rules skip entropy checks and the global allowlists: the user asked
 * for exactly this. Exclusions still apply to them.
 */
export function compileUserRules(lines: readonly string[] | undefined): CompiledUserRules {
  const rules: Rule[] = [];
  const errors: ExclusionError[] = [];
  if (!lines) return { rules, errors };

  lines.forEach((raw, i) => {
    const parsed = parseUserPattern(raw);
    if (!parsed) return;
    // g for matchAll, d for group offsets; y would anchor every match to lastIndex
    const flags = [...new Set(parsed.flags.replace(/[gy]/g, "") + "gd")].join("");
    let regex: RegExp;
    try {
      regex = new RegExp(parsed.source, flags);
    } catch (e) {
      errors.push({ line: i + 1, pattern: parsed.line, message: e instanceof Error ? e.message : String(e) });
      return;
    }
    rules.push({
      id: USER_RULE_ID,
      description: `User rule (line ${i + 1})`,
      regex,
      secretGroup: 0,
      entropy: 0,
      keywords: [],
      allowlists: [],
      // what the user explicitly listed wins over generic built-in matches when they overlap
      specificity: Specificity.Specific,
      prefixes: [],
      requireDigit: false,
      category: "secret",
      user: true,
    });
  });
  return { rules, errors };
}
