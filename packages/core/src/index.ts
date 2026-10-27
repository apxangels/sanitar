/**
 * @sanitar/core — finds secrets in text and replaces them.
 *
 * No DOM, no Node APIs: the same code runs in the browser, in Node and in an
 * MV3 extension service worker. Randomness comes from globalThis.crypto only.
 */
import { detect } from "./detect.js";
import { compileExclusions, isExcluded } from "./exclusions.js";
import { assertInputSize, PREVIEW_MIN_LENGTH, PREVIEW_PREFIX_LENGTH } from "./limits.js";
import { applyReplacements, mergeOverlaps, withoutOverlaps, type Region } from "./replace.js";
import type { Finding, Mode, SanitizeOptions, SanitizeResult, ScanOptions, ScanResult } from "./types.js";

export type { ExclusionError, Finding, Mode, SanitizeOptions, SanitizeResult, ScanOptions, ScanResult } from "./types.js";
export { InputTooLargeError, MAX_INPUT_BYTES, utf8ByteLength } from "./limits.js";
export { compileExclusions } from "./exclusions.js";
export { shannonEntropy } from "./entropy.js";
export { GITLEAKS_VERSION } from "./rules/index.js";

export const DEFAULT_PLACEHOLDER = "<secret>";
export const MODES: readonly Mode[] = ["placeholder", "erase", "random"];

export function preview(secret: string): string {
  if (secret.length < PREVIEW_MIN_LENGTH) return "…";
  return secret.slice(0, PREVIEW_PREFIX_LENGTH) + "…";
}

function lineIndex(text: string): (offset: number) => number {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

interface Analysis extends ScanResult {
  regions: Region[];
}

function analyze(text: string, exclusions: readonly string[] | undefined): Analysis {
  assertInputSize(text);
  const ex = compileExclusions(exclusions);
  const raw = detect(text);

  const kept = [];
  const dropped = [];
  for (const f of raw) {
    if (ex.regexes.length > 0 && isExcluded(text.slice(f.start, f.end), ex)) dropped.push(f);
    else kept.push(f);
  }

  const regions = mergeOverlaps(kept);
  // an excluded match that overlaps a replaced region is replaced anyway; don't list it as excluded
  const excludedRegions = withoutOverlaps(mergeOverlaps(dropped), regions);

  const lineOf = lineIndex(text);
  const toFinding = (r: Region): Finding => ({
    ruleId: r.rule.id,
    description: r.rule.description,
    start: r.start,
    end: r.end,
    line: lineOf(r.start),
    preview: preview(text.slice(r.start, r.end)),
  });

  return {
    regions,
    findings: regions.map(toFinding),
    excluded: excludedRegions.map(toFinding),
    errors: ex.errors,
  };
}

/** Finds secrets without changing the text. */
export function scan(text: string, opts: ScanOptions = {}): ScanResult {
  const { findings, excluded, errors } = analyze(text, opts.exclusions);
  return { findings, excluded, errors };
}

/** Finds secrets and replaces them according to `opts.mode`. */
export function sanitize(text: string, opts: SanitizeOptions): SanitizeResult {
  if (!MODES.includes(opts.mode)) throw new Error(`unknown mode: ${String(opts.mode)}`);
  const { regions, findings, excluded, errors } = analyze(text, opts.exclusions);
  const out = applyReplacements(text, regions, {
    mode: opts.mode,
    placeholder: opts.placeholder || DEFAULT_PLACEHOLDER,
    placeholderWithType: opts.placeholderWithType ?? false,
  });
  return { text: out, findings, excluded, errors };
}
