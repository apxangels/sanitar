/**
 * Downloads gitleaks' default config (config/gitleaks.toml, MIT license) for a
 * pinned version, converts the Go RE2 regexes into JS RegExp sources and writes
 * packages/core/src/rules/gitleaks.json.
 *
 * Usage: pnpm import-rules [--file path/to/gitleaks.toml]
 *
 * Rules that can't be converted are reported and left out. The script fails if
 * any rule that made it into the JSON doesn't compile as a JS RegExp.
 */
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { convertRe2, Re2ConversionError } from "./lib/re2-to-js.ts";

export const GITLEAKS_VERSION = "v8.30.1";
const SOURCE_URL = `https://raw.githubusercontent.com/gitleaks/gitleaks/${GITLEAKS_VERSION}/config/gitleaks.toml`;
const OUT_FILE = fileURLToPath(new URL("../packages/core/src/rules/gitleaks.json", import.meta.url));

/** Rule ids we drop on purpose (e.g. too slow in a backtracking engine). */
const SKIP_RULES: Record<string, string> = {};

interface TomlAllowlist {
  description?: string;
  condition?: string;
  regexTarget?: string;
  regexes?: string[];
  stopwords?: string[];
  paths?: string[];
  commits?: string[];
}

interface TomlRule {
  id: string;
  description?: string;
  regex?: string;
  secretGroup?: number;
  entropy?: number;
  keywords?: string[];
  path?: string;
  allowlists?: TomlAllowlist[];
  /** old single-allowlist syntax */
  allowlist?: TomlAllowlist;
}

interface OutRegex {
  source: string;
  flags: string;
}

interface OutAllowlist {
  condition: "OR" | "AND";
  regexTarget: "secret" | "match" | "line";
  regexes: OutRegex[];
  stopwords: string[];
}

interface OutRule {
  id: string;
  description: string;
  regex: string;
  flags: string;
  secretGroup: number;
  entropy: number;
  keywords: string[];
  allowlists: OutAllowlist[];
}

const problems: string[] = [];
const notes: string[] = [];

/**
 * Rewrites that keep the matched language identical but avoid slow
 * backtracking in JS (RE2 is linear-time, JS engines are not).
 */
function optimize(source: string): string {
  // `[\w.-]{0,50}?(?:[\w.-]{0,50}?` (a gitleaks generator artifact when a
  // keyword group is wrapped in (?i:...)) is `[\w.-]{0,100}?` — but as two nested
  // lazy loops it costs 50×50 steps per position instead of 100.
  return source.replace(/\[\\w\\\.\\-\]\{0,50\}\?\(\?:\[\\w\\\.\\-\]\{0,50\}\?/g, "(?:[\\w\\.\\-]{0,100}?");
}

function convert(pattern: string, where: string): OutRegex | null {
  try {
    const conv = convertRe2(pattern);
    const r = { source: optimize(conv.source), flags: conv.flags };
    new RegExp(r.source, r.flags + "gd");
    return r;
  } catch (e) {
    const msg = e instanceof Re2ConversionError || e instanceof SyntaxError ? e.message : String(e);
    problems.push(`${where}: ${msg}`);
    return null;
  }
}

/**
 * Converts an allowlist. Returns null when the allowlist can never apply to
 * pasted text (e.g. it only matches file paths or commits).
 */
function convertAllowlist(al: TomlAllowlist, where: string): OutAllowlist | null {
  const condition = (al.condition ?? "OR").toUpperCase() === "AND" ? "AND" : "OR";
  const target = (al.regexTarget ?? "secret") as OutAllowlist["regexTarget"];
  if (!["secret", "match", "line"].includes(target)) {
    problems.push(`${where}: unknown regexTarget ${target}`);
    return null;
  }
  const hasPathOrCommit = (al.paths?.length ?? 0) > 0 || (al.commits?.length ?? 0) > 0;
  if (condition === "AND" && hasPathOrCommit) {
    // AND with a path/commit check can never be satisfied for pasted text.
    notes.push(`${where}: allowlist with condition=AND on paths/commits skipped (no file paths in pasted text)`);
    return null;
  }
  const regexes: OutRegex[] = [];
  for (const [i, re] of (al.regexes ?? []).entries()) {
    const c = convert(re, `${where} regex #${i}`);
    if (!c) return null; // a half-converted allowlist would change semantics
    regexes.push(c);
  }
  const stopwords = (al.stopwords ?? []).map((w) => w.toLowerCase());
  if (regexes.length === 0 && stopwords.length === 0) {
    if (hasPathOrCommit) notes.push(`${where}: path/commit-only allowlist skipped`);
    return null;
  }
  return { condition, regexTarget: target, regexes, stopwords };
}

async function loadToml(): Promise<string> {
  const fileArg = process.argv.indexOf("--file");
  if (fileArg !== -1 && process.argv[fileArg + 1]) {
    return readFile(process.argv[fileArg + 1]!, "utf8");
  }
  console.log(`Downloading ${SOURCE_URL}`);
  const res = await fetch(SOURCE_URL);
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  return res.text();
}

async function main(): Promise<void> {
  const raw = await loadToml();
  const toml = parseToml(raw) as unknown as { allowlist?: TomlAllowlist; allowlists?: TomlAllowlist[]; rules: TomlRule[] };

  const rules: OutRule[] = [];
  let skipped = 0;

  for (const rule of toml.rules) {
    const where = `rule ${rule.id}`;
    if (SKIP_RULES[rule.id]) {
      notes.push(`${where}: skipped on purpose (${SKIP_RULES[rule.id]})`);
      skipped++;
      continue;
    }
    if (!rule.regex) {
      notes.push(`${where}: no regex (path-only rule), skipped`);
      skipped++;
      continue;
    }
    if (rule.path) {
      notes.push(`${where}: path filter "${rule.path}" ignored (pasted text has no file name)`);
    }
    const re = convert(rule.regex, where);
    if (!re) {
      skipped++;
      continue;
    }
    const allowlists: OutAllowlist[] = [];
    const rawAllowlists = [...(rule.allowlists ?? []), ...(rule.allowlist ? [rule.allowlist] : [])];
    let broken = false;
    for (const [i, al] of rawAllowlists.entries()) {
      const before = problems.length;
      const c = convertAllowlist(al, `${where} allowlist #${i}`);
      if (problems.length > before) broken = true;
      if (c) allowlists.push(c);
    }
    if (broken) {
      // Dropping an allowlist would silently increase false positives; drop the rule instead.
      problems.push(`${where}: skipped because one of its allowlists can't be converted`);
      skipped++;
      continue;
    }
    rules.push({
      id: rule.id,
      description: rule.description ?? rule.id,
      regex: re.source,
      flags: re.flags,
      secretGroup: rule.secretGroup ?? 0,
      entropy: rule.entropy ?? 0,
      keywords: (rule.keywords ?? []).map((k) => k.toLowerCase()),
      allowlists,
    });
  }

  const globalRaw = [...(toml.allowlist ? [toml.allowlist] : []), ...(toml.allowlists ?? [])];
  const globalAllowlists: OutAllowlist[] = [];
  for (const [i, al] of globalRaw.entries()) {
    const c = convertAllowlist(al, `global allowlist #${i}`);
    if (c) globalAllowlists.push(c);
  }

  // Final safety net: every emitted regex must compile with the flags core uses.
  for (const rule of rules) {
    try {
      new RegExp(rule.regex, rule.flags + "gd");
      for (const al of rule.allowlists) for (const r of al.regexes) new RegExp(r.source, r.flags);
    } catch (e) {
      throw new Error(`rule ${rule.id} does not compile: ${(e as Error).message}`);
    }
  }
  for (const al of globalAllowlists) for (const r of al.regexes) new RegExp(r.source, r.flags);

  const out = {
    $comment: "Generated by scripts/import-gitleaks-rules.ts from gitleaks config/gitleaks.toml (MIT). Do not edit by hand.",
    gitleaksVersion: GITLEAKS_VERSION,
    globalAllowlists,
    rules,
  };
  await writeFile(OUT_FILE, JSON.stringify(out, null, 1) + "\n");

  for (const n of notes) console.log(`note: ${n}`);
  for (const p of problems) console.warn(`SKIPPED: ${p}`);
  console.log(
    `gitleaks ${GITLEAKS_VERSION}: ${toml.rules.length} rules in source, ${rules.length} written, ${skipped} skipped → ${OUT_FILE}`,
  );
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
