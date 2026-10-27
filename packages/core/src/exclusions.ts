import type { ExclusionError } from "./types.js";

export interface CompiledExclusions {
  regexes: RegExp[];
  errors: ExclusionError[];
}

// only valid JS flag letters, so a path like "/usr/bin" stays a plain pattern
const SLASH_FORM = /^\/(.+)\/([dgimsuvy]*)$/s;

/**
 * Compiles user exclusions. Each entry is a regex source, or "/pattern/flags".
 * Empty entries are ignored. Invalid entries are reported in `errors` (with the
 * 1-based line number) and skipped; the rest still apply.
 */
export function compileExclusions(lines: readonly string[] | undefined): CompiledExclusions {
  const regexes: RegExp[] = [];
  const errors: ExclusionError[] = [];
  if (!lines) return { regexes, errors };

  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (line === "") return;
    let source = line;
    let flags = "";
    const m = SLASH_FORM.exec(line);
    if (m) {
      source = m[1]!;
      // g/y make .test() stateful, which would make results depend on order
      flags = m[2]!.replace(/[gy]/g, "");
    }
    try {
      regexes.push(new RegExp(source, flags));
    } catch (e) {
      errors.push({ line: i + 1, pattern: line, message: e instanceof Error ? e.message : String(e) });
    }
  });
  return { regexes, errors };
}

/** true if any exclusion matches (anywhere in) the secret value */
export function isExcluded(secret: string, ex: CompiledExclusions): boolean {
  for (const re of ex.regexes) if (re.test(secret)) return true;
  return false;
}
