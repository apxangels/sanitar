/**
 * Converts a Go RE2 regular expression (as used in gitleaks.toml) into an
 * equivalent JavaScript RegExp source + flags.
 *
 * Handled RE2 features:
 *   - inline flags `(?i)`, `(?s)`, `(?-i)` anywhere (scoped to the rest of the
 *     enclosing group, like RE2) and flag groups `(?i:...)`, `(?-i:...)`, `(?s:...)`.
 *     Case-insensitive parts are expanded by hand (`a` → `[aA]`) unless the whole
 *     pattern is case-insensitive, in which case the JS `i` flag is used.
 *     JS regexp modifiers `(?i:...)` are not used on purpose: older runtimes
 *     (Node 20, Safari) do not support them.
 *   - `\z` → `$`, `\A` → `^` (no `m` flag in JS, so these are equivalent)
 *   - POSIX classes `[[:alnum:]]` etc.
 *   - `]` as the first char of a class (`[]a]`, `[^]]`), which means something
 *     different in JS (`[^]` is "any char" there).
 *   - `(?P<name>...)` → `(?<name>...)`
 *   - stray `{` / `}` that RE2 treats as literals are escaped.
 *
 * Anything we can't translate faithfully throws Re2ConversionError. The caller
 * is expected to log it and skip the rule rather than ship a broken regex.
 */

export class Re2ConversionError extends Error {
  override name = "Re2ConversionError";
}

export interface JsRegex {
  source: string;
  /** Only "i" or "". Callers add "g"/"d" themselves. */
  flags: string;
}

interface Flags {
  i: boolean;
  s: boolean;
}

type ClassItem =
  | { kind: "range"; from: number; to: number }
  | { kind: "raw"; text: string }; // \w, \d, \s, \W ... (no case folding needed)

const POSIX: Record<string, ClassItem[]> = {
  alnum: [r("0", "9"), r("A", "Z"), r("a", "z")],
  alpha: [r("A", "Z"), r("a", "z")],
  ascii: [{ kind: "range", from: 0, to: 0x7f }],
  blank: [r(" ", " "), r("\t", "\t")],
  cntrl: [{ kind: "range", from: 0, to: 0x1f }, { kind: "range", from: 0x7f, to: 0x7f }],
  digit: [r("0", "9")],
  graph: [r("!", "~")],
  lower: [r("a", "z")],
  print: [r(" ", "~")],
  punct: [r("!", "/"), r(":", "@"), r("[", "`"), r("{", "~")],
  space: [{ kind: "raw", text: "\\t\\n\\v\\f\\r " }],
  upper: [r("A", "Z")],
  word: [{ kind: "raw", text: "\\w" }],
  xdigit: [r("0", "9"), r("A", "F"), r("a", "f")],
};

function r(a: string, b: string): ClassItem {
  return { kind: "range", from: a.charCodeAt(0), to: b.charCodeAt(0) };
}

const A = 0x41, Z = 0x5a, a = 0x61, z = 0x7a;

export function convertRe2(pattern: string): JsRegex {
  // Decide whether the whole pattern is case-insensitive: it starts with a
  // flag group that sets `i` and never turns it off.
  const lead = /^\(\?([a-zA-Z]+)\)/.exec(pattern);
  const allInsensitive = !!lead && lead[1]!.includes("i") && !/\(\?[a-zA-Z]*-/.test(pattern);

  const conv = new Converter(pattern, allInsensitive);
  const source = conv.run();
  return { source, flags: allInsensitive ? "i" : "" };
}

class Converter {
  private pos = 0;
  private out = "";
  /** flag stack: one entry per open group; top = current scope */
  private stack: Flags[] = [{ i: false, s: false }];

  constructor(private readonly src: string, private readonly nativeI: boolean) {}

  private get flags(): Flags {
    return this.stack[this.stack.length - 1]!;
  }

  /** case folding is done by hand only when the JS `i` flag isn't used */
  private get fold(): boolean {
    return this.flags.i && !this.nativeI;
  }

  run(): string {
    const s = this.src;
    while (this.pos < s.length) {
      const c = s[this.pos]!;
      switch (c) {
        case "\\":
          this.escapeOutside();
          break;
        case "[":
          this.charClass();
          break;
        case "(":
          this.openGroup();
          break;
        case ")":
          if (this.stack.length === 1) throw new Re2ConversionError("unbalanced ')'");
          this.stack.pop();
          this.out += ")";
          this.pos++;
          break;
        case ".":
          this.out += this.flags.s ? "[\\s\\S]" : ".";
          this.pos++;
          break;
        case "{": {
          const q = /^\{(\d+)(,(\d*))?\}/.exec(s.slice(this.pos));
          if (q) {
            this.out += q[0];
            this.pos += q[0].length;
          } else {
            this.out += "\\{";
            this.pos++;
          }
          break;
        }
        case "}":
        case "]":
          this.out += "\\" + c;
          this.pos++;
          break;
        case "/":
          this.out += "\\/";
          this.pos++;
          break;
        default:
          this.literal(c);
          this.pos++;
      }
    }
    if (this.stack.length !== 1) throw new Re2ConversionError("unbalanced '('");
    return this.out;
  }

  private literal(c: string): void {
    const code = c.charCodeAt(0);
    if (this.fold && isLetter(code)) {
      this.out += `[${c.toLowerCase()}${c.toUpperCase()}]`;
    } else {
      this.out += c;
    }
  }

  private escapeOutside(): void {
    const s = this.src;
    const n = s[this.pos + 1];
    if (n === undefined) throw new Re2ConversionError("trailing backslash");
    switch (n) {
      case "z":
        this.out += "$";
        this.pos += 2;
        return;
      case "A":
        this.out += "^";
        this.pos += 2;
        return;
      case "Q":
      case "C":
      case "p":
      case "P":
      case "Z":
        throw new Re2ConversionError(`unsupported escape \\${n}`);
      case "x": {
        const m = /^\\x([0-9a-fA-F]{2})/.exec(s.slice(this.pos));
        if (!m) throw new Re2ConversionError("unsupported \\x form");
        const code = parseInt(m[1]!, 16);
        if (this.fold && isLetter(code)) this.literal(String.fromCharCode(code));
        else this.out += m[0];
        this.pos += m[0].length;
        return;
      }
      default:
        if (/[0-9]/.test(n) && n !== "0") throw new Re2ConversionError("backreference/octal not supported");
        this.out += "\\" + n;
        this.pos += 2;
    }
  }

  private openGroup(): void {
    const s = this.src;
    const rest = s.slice(this.pos);
    if (!rest.startsWith("(?")) {
      this.stack.push({ ...this.flags });
      this.out += "(";
      this.pos++;
      return;
    }
    if (rest.startsWith("(?:")) {
      this.stack.push({ ...this.flags });
      this.out += "(?:";
      this.pos += 3;
      return;
    }
    const named = /^\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>/.exec(rest);
    if (named) {
      this.stack.push({ ...this.flags });
      this.out += `(?<${named[1]}>`;
      this.pos += named[0].length;
      return;
    }
    const fl = /^\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?(\)|:)/.exec(rest);
    if (!fl) throw new Re2ConversionError(`unsupported group syntax near "${rest.slice(0, 6)}"`);
    const on = fl[1] ?? "";
    const off = fl[2] ?? "";
    const next: Flags = { ...this.flags };
    for (const f of on) this.applyFlag(next, f, true);
    for (const f of off) this.applyFlag(next, f, false);
    if (this.nativeI && !next.i) {
      // can't happen: nativeI is only chosen when `-i` never appears
      throw new Re2ConversionError("internal: case-sensitive scope inside native i");
    }
    this.pos += fl[0].length;
    if (fl[3] === ")") {
      // (?flags) — applies to the rest of the current group
      this.stack[this.stack.length - 1] = next;
    } else {
      this.stack.push(next);
      this.out += "(?:";
    }
  }

  private applyFlag(target: Flags, f: string, on: boolean): void {
    if (f === "i") target.i = on;
    else if (f === "s") target.s = on;
    else throw new Re2ConversionError(`unsupported inline flag "${f}"`);
  }

  private charClass(): void {
    const s = this.src;
    let p = this.pos + 1;
    let negated = false;
    if (s[p] === "^") {
      negated = true;
      p++;
    }
    const items: ClassItem[] = [];
    let first = true;
    for (;;) {
      if (p >= s.length) throw new Re2ConversionError("unterminated character class");
      const c = s[p]!;
      if (c === "]" && !first) {
        p++;
        break;
      }
      first = false;
      if (c === "[" && s[p + 1] === ":") {
        const m = /^\[:(\^)?([a-z]+):\]/.exec(s.slice(p));
        if (!m) throw new Re2ConversionError("bad POSIX class");
        if (m[1]) throw new Re2ConversionError("negated POSIX class not supported");
        const cls = POSIX[m[2]!];
        if (!cls) throw new Re2ConversionError(`unknown POSIX class ${m[2]}`);
        items.push(...cls);
        p += m[0].length;
        continue;
      }
      // single atom: escape or char
      const [lo, adv] = this.classAtom(p);
      p += adv;
      if (lo.kind === "range" && s[p] === "-" && s[p + 1] !== undefined && s[p + 1] !== "]") {
        const [hi, adv2] = this.classAtom(p + 1);
        if (hi.kind !== "range") throw new Re2ConversionError("bad class range");
        if (hi.from < lo.from) throw new Re2ConversionError("inverted class range");
        items.push({ kind: "range", from: lo.from, to: hi.from });
        p += 1 + adv2;
      } else {
        items.push(lo);
      }
    }
    this.pos = p;

    const finalItems = this.fold ? foldItems(items) : items;
    this.out += "[" + (negated ? "^" : "") + finalItems.map(emitItem).join("") + "]";
  }

  /** returns [item, consumed chars] for a single class atom at position p */
  private classAtom(p: number): [ClassItem, number] {
    const s = this.src;
    const c = s[p]!;
    if (c !== "\\") {
      const code = c.charCodeAt(0);
      return [{ kind: "range", from: code, to: code }, 1];
    }
    const n = s[p + 1];
    if (n === undefined) throw new Re2ConversionError("trailing backslash in class");
    if (n === "x") {
      const m = /^\\x([0-9a-fA-F]{2})/.exec(s.slice(p));
      if (!m) throw new Re2ConversionError("unsupported \\x form in class");
      const code = parseInt(m[1]!, 16);
      return [{ kind: "range", from: code, to: code }, m[0].length];
    }
    const simple: Record<string, number> = { n: 10, r: 13, t: 9, f: 12, v: 11, a: 7 };
    if (n in simple) {
      const code = simple[n]!;
      return [{ kind: "range", from: code, to: code }, 2];
    }
    if ("wWdDsS".includes(n)) return [{ kind: "raw", text: "\\" + n }, 2];
    if (/[A-Za-z0-9]/.test(n)) throw new Re2ConversionError(`unsupported escape \\${n} in class`);
    // escaped punctuation: literal
    const code = n.charCodeAt(0);
    return [{ kind: "range", from: code, to: code }, 2];
  }
}

function isLetter(code: number): boolean {
  return (code >= A && code <= Z) || (code >= a && code <= z);
}

function foldItems(items: ClassItem[]): ClassItem[] {
  const out: ClassItem[] = [...items];
  for (const it of items) {
    if (it.kind !== "range") continue;
    // uppercase part → add lowercase
    const u0 = Math.max(it.from, A), u1 = Math.min(it.to, Z);
    if (u0 <= u1) out.push({ kind: "range", from: u0 + 32, to: u1 + 32 });
    const l0 = Math.max(it.from, a), l1 = Math.min(it.to, z);
    if (l0 <= l1) out.push({ kind: "range", from: l0 - 32, to: l1 - 32 });
  }
  return dedupe(out);
}

function dedupe(items: ClassItem[]): ClassItem[] {
  const seen = new Set<string>();
  const out: ClassItem[] = [];
  for (const it of items) {
    const key = it.kind === "raw" ? it.text : `${it.from}-${it.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

function emitChar(code: number): string {
  const ch = String.fromCharCode(code);
  if (/[A-Za-z0-9 _!"#%&',:;<=>@`~]/.test(ch)) return ch;
  if (code < 0x20 || code === 0x7f || code > 0x7e) {
    return code <= 0xff ? "\\x" + code.toString(16).padStart(2, "0") : "\\u" + code.toString(16).padStart(4, "0");
  }
  // escape everything else that might be special inside a JS class
  return "\\" + ch;
}

function emitItem(it: ClassItem): string {
  if (it.kind === "raw") return it.text;
  if (it.from === it.to) return emitChar(it.from);
  return emitChar(it.from) + "-" + emitChar(it.to);
}
