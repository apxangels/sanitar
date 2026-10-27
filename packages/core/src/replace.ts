import type { RawFinding } from "./detect.js";
import type { Rule } from "./rules/index.js";
import type { Mode } from "./types.js";

/** A merged region of text to replace, attributed to the most specific rule. */
export interface Region {
  start: number;
  end: number;
  rule: Rule;
}

function better(a: RawFinding, b: RawFinding): RawFinding {
  if (a.rule.specificity !== b.rule.specificity) return a.rule.specificity > b.rule.specificity ? a : b;
  const la = a.end - a.start;
  const lb = b.end - b.start;
  if (la !== lb) return la > lb ? a : b;
  return a.ruleIndex <= b.ruleIndex ? a : b;
}

/**
 * Merges overlapping findings into one region spanning all of them. The region
 * keeps the most specific rule: generic rules lose to concrete ones, then the
 * longer match wins, then the rule defined first.
 */
export function mergeOverlaps(findings: readonly RawFinding[]): Region[] {
  const sorted = [...findings].sort((x, y) => x.start - y.start || y.end - x.end);
  const out: Region[] = [];
  let cur: { start: number; end: number; winner: RawFinding } | null = null;
  for (const f of sorted) {
    if (cur && f.start < cur.end) {
      cur.end = Math.max(cur.end, f.end);
      cur.winner = better(cur.winner, f);
    } else {
      if (cur) out.push({ start: cur.start, end: cur.end, rule: cur.winner.rule });
      cur = { start: f.start, end: f.end, winner: f };
    }
  }
  if (cur) out.push({ start: cur.start, end: cur.end, rule: cur.winner.rule });
  return out;
}

/** Drops regions that overlap any region in `kept` (both sorted by start). */
export function withoutOverlaps(regions: readonly Region[], kept: readonly Region[]): Region[] {
  return regions.filter((r) => {
    // binary search for the first kept region that ends after r.start
    let lo = 0;
    let hi = kept.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (kept[mid]!.end <= r.start) lo = mid + 1;
      else hi = mid;
    }
    const k = kept[lo];
    return !(k && k.start < r.end);
  });
}

export interface ReplaceOptions {
  mode: Mode;
  placeholder: string;
  placeholderWithType: boolean;
}

/** "<secret>" + "aws-access-token" → "<secret:aws-access-token>"; "{{X}}" → "{{X:id}}"; "X" → "X:id" */
export function typedPlaceholder(placeholder: string, ruleId: string): string {
  const m = /^([\s\S]*?)([>\])}]+)$/.exec(placeholder);
  return m ? `${m[1]}:${ruleId}${m[2]}` : `${placeholder}:${ruleId}`;
}

/**
 * Applies replacements from the end of the text to the start, so offsets in
 * `regions` (all relative to the original text) stay valid.
 */
export function applyReplacements(text: string, regions: readonly Region[], opts: ReplaceOptions): string {
  if (regions.length === 0) return text;
  const sorted = [...regions].sort((a, b) => b.start - a.start);
  const parts: string[] = [];
  let tail = text.length;
  for (const r of sorted) {
    parts.push(text.slice(r.end, tail));
    parts.push(replacementFor(text.slice(r.start, r.end), r.rule, opts));
    tail = r.start;
  }
  parts.push(text.slice(0, tail));
  return parts.reverse().join("");
}

function replacementFor(secret: string, rule: Rule, opts: ReplaceOptions): string {
  switch (opts.mode) {
    case "placeholder":
      return opts.placeholderWithType ? typedPlaceholder(opts.placeholder, rule.id) : opts.placeholder;
    case "erase":
      return "";
    case "random":
      return randomLike(secret, rule);
    default:
      throw new Error(`unknown mode: ${String(opts.mode)}`);
  }
}

// ---------------------------------------------------------------------------
// random mode

interface CryptoLike {
  getRandomValues(array: Uint8Array): Uint8Array;
}

function getCrypto(): CryptoLike {
  const c = (globalThis as { crypto?: CryptoLike }).crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("globalThis.crypto.getRandomValues is not available");
  }
  return c;
}

/** Uniform random integers in [0, n) via rejection sampling (n ≤ 256). */
function randomInts(count: number, n: number): number[] {
  const crypto = getCrypto();
  const limit = 256 - (256 % n);
  const out: number[] = [];
  // getRandomValues accepts at most 65536 bytes per call
  const buf = new Uint8Array(Math.min(65536, Math.max(16, count * 2)));
  while (out.length < count) {
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < limit) {
        out.push(b % n);
        if (out.length === count) break;
      }
    }
  }
  return out;
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = LOWER.toUpperCase();
const DIGITS = "0123456789";

function classOf(ch: string): string | null {
  if (ch >= "a" && ch <= "z") return LOWER;
  if (ch >= "A" && ch <= "Z") return UPPER;
  if (ch >= "0" && ch <= "9") return DIGITS;
  return null;
}

/**
 * Same length and character classes as `secret`: letters stay letters of the
 * same case, digits stay digits, everything else (-_/+=. etc.) stays in place.
 * Known prefixes (ghp_, AKIA…) and rule-defined parts (PEM armor) are kept.
 */
export function randomLike(secret: string, rule: Pick<Rule, "prefixes" | "preserve">): string {
  const keep = new Uint8Array(secret.length);

  const lower = secret.toLowerCase();
  let prefixLen = 0;
  for (const p of rule.prefixes) {
    // don't keep a "prefix" that is half the secret
    if (p.length > prefixLen && p.length * 2 <= secret.length && lower.startsWith(p)) prefixLen = p.length;
  }
  keep.fill(1, 0, prefixLen);

  if (rule.preserve) {
    const re = rule.preserve.global ? rule.preserve : new RegExp(rule.preserve.source, rule.preserve.flags + "g");
    for (const m of secret.matchAll(re)) keep.fill(1, m.index!, m.index! + m[0].length);
  }

  const slots: { i: number; alphabet: string }[] = [];
  for (let i = 0; i < secret.length; i++) {
    if (keep[i]) continue;
    const alphabet = classOf(secret[i]!);
    if (alphabet) slots.push({ i, alphabet });
  }
  if (slots.length === 0) return secret;

  // a short secret could randomly come out identical; retry a few times
  for (let attempt = 0; attempt < 8; attempt++) {
    const chars = secret.split("");
    const byLen = new Map<number, number[]>();
    for (const len of [26, 10]) {
      const need = slots.filter((s) => s.alphabet.length === len).length;
      if (need) byLen.set(len, randomInts(need, len));
    }
    const cursor = new Map<number, number>([[26, 0], [10, 0]]);
    for (const s of slots) {
      const len = s.alphabet.length;
      const pos = cursor.get(len)!;
      chars[s.i] = s.alphabet[byLen.get(len)![pos]!]!;
      cursor.set(len, pos + 1);
    }
    const result = chars.join("");
    if (result !== secret) return result;
  }
  return secret.replace(/[A-Za-z0-9]/g, (c) => (classOf(c) === DIGITS ? "0" : c === c.toLowerCase() ? "x" : "X"));
}
