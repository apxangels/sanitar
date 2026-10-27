import { shannonEntropy } from "./entropy.js";
import { getRules, type Allowlist, type Rule } from "./rules/index.js";
import { stopwordMatcher } from "./stopwords.js";

/** A single rule match before exclusions and merging. */
export interface RawFinding {
  rule: Rule;
  /** position of the rule in the rule list; lower = defined earlier */
  ruleIndex: number;
  start: number;
  end: number;
}

interface MatchContext {
  secret: string;
  match: string;
  /** whole line(s) the match spans; computed lazily */
  line: () => string;
}

function secretSpan(m: RegExpExecArray | RegExpMatchArray, secretGroup: number): [number, number] | null {
  const idx = (m as RegExpExecArray).indices;
  if (!idx) return null;
  if (secretGroup > 0) {
    const g = idx[secretGroup];
    return g && g[1] > g[0] ? [g[0], g[1]] : null;
  }
  // first non-empty capture group, else the whole match (gitleaks semantics)
  for (let i = 1; i < idx.length; i++) {
    const g = idx[i];
    if (g && g[1] > g[0]) return [g[0], g[1]];
  }
  const whole = idx[0]!;
  return whole[1] > whole[0] ? [whole[0], whole[1]] : null;
}

function allowedBy(al: Allowlist, ctx: MatchContext): boolean {
  let regexHit = false;
  if (al.regexes.length > 0) {
    const target = al.regexTarget === "match" ? ctx.match : al.regexTarget === "line" ? ctx.line() : ctx.secret;
    regexHit = al.regexes.some((re) => re.test(target));
  }
  let stopHit = false;
  if (al.stopwords.length > 0) {
    stopHit = stopwordMatcher(al.stopwords)(ctx.secret.toLowerCase());
  }
  if (al.condition === "AND") {
    return (al.regexes.length === 0 || regexHit) && (al.stopwords.length === 0 || stopHit);
  }
  return regexHit || stopHit;
}

/** [\w.-] */
function isPrefixChar(c: number): boolean {
  return (
    (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 46 || c === 45
  );
}

function lineAround(text: string, start: number, end: number): string {
  const ls = text.lastIndexOf("\n", start - 1) + 1;
  let le = text.indexOf("\n", end);
  if (le === -1) le = text.length;
  return text.slice(ls, le);
}

/**
 * Runs every rule over the text: keyword prefilter → regex → entropy →
 * validate → rule allowlists → global allowlists. Returns raw (possibly overlapping)
 * findings in rule order.
 */
export function detect(text: string, onlyRules?: ReadonlySet<string>, includePii = true): RawFinding[] {
  if (text.length === 0) return [];
  const { rules, globalAllowlists } = getRules();
  const lower = text.toLowerCase();
  const keywordSeen = new Map<string, boolean>();
  const hasKeyword = (k: string): boolean => {
    let v = keywordSeen.get(k);
    if (v === undefined) {
      v = lower.includes(k);
      keywordSeen.set(k, v);
    }
    return v;
  };

  const out: RawFinding[] = [];
  rules.forEach((rule, ruleIndex) => {
    if (onlyRules && !onlyRules.has(rule.id)) return;
    if (!includePii && rule.category === "pii") return;
    if (rule.keywords.length > 0 && !rule.keywords.some(hasKeyword)) return;

    let prevEnd = 0;
    for (const m of text.matchAll(rule.regex)) {
      const mEnd = m.index! + m[0].length;
      let mStart = m.index!;
      if (rule.leftExtend) {
        // restore the lazy `[\w.-]{0,N}?` prefix: it can't reach into the previous match
        const limit = Math.max(prevEnd, mStart - rule.leftExtend);
        while (mStart > limit && isPrefixChar(text.charCodeAt(mStart - 1))) mStart--;
      }
      prevEnd = mEnd;

      const span = secretSpan(m, rule.secretGroup);
      if (!span) continue;
      const [start, end] = span;
      const secret = text.slice(start, end);
      if (rule.validate && !rule.validate(secret)) continue;

      if (rule.entropy > 0) {
        if (shannonEntropy(secret) <= rule.entropy) continue;
        if (rule.requireDigit && !/\d/.test(secret)) continue;
      }

      let lineCache: string | undefined;
      const ctx: MatchContext = {
        secret,
        match: text.slice(mStart, mEnd),
        line: () => (lineCache ??= lineAround(text, mStart, mEnd)),
      };
      if (rule.allowlists.some((al) => allowedBy(al, ctx))) continue;
      if (globalAllowlists.some((al) => allowedBy(al, ctx))) continue;

      out.push({ rule, ruleIndex, start, end });
    }
  });
  return out;
}
