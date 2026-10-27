export type RegexTarget = "secret" | "match" | "line";

export interface Allowlist {
  condition: "OR" | "AND";
  regexTarget: RegexTarget;
  /** compiled without g/y so `.test()` is stateless */
  regexes: RegExp[];
  /** lowercase; a secret containing any of them is allowed */
  stopwords: string[];
}

/**
 * How much a rule "knows" about the secret. Used when overlapping findings are
 * merged: the higher one wins.
 */
export const Specificity = {
  /** catch-alls like generic-api-key or "password=" */
  Generic: 0,
  /** structural hints (Authorization header, URL credentials) */
  Contextual: 1,
  /** a concrete service/token format */
  Specific: 2,
} as const;
export type Specificity = (typeof Specificity)[keyof typeof Specificity];

/** "secret": credentials. "pii": personal data (emails, phones, names…), can be switched off. */
export type Category = "secret" | "pii";

export interface Rule {
  id: string;
  description: string;
  /** compiled with g + d */
  regex: RegExp;
  /**
   * Set when the original pattern started with a lazy `[\w.-]{0,N}?` prefix.
   * `regex` is then the pattern without that prefix, and the match start is
   * found by scanning left at most N word/./- chars. This gives the same
   * matches without the N steps of backtracking at every text position.
   */
  leftExtend?: number;
  /** 0 = first non-empty group, or the whole match if there are no groups */
  secretGroup: number;
  /** minimum Shannon entropy; 0 = no check */
  entropy: number;
  /** lowercase; empty = always run */
  keywords: string[];
  allowlists: Allowlist[];
  specificity: Specificity;
  /**
   * Known prefixes kept as-is in "random" mode (e.g. "ghp_"). Matched
   * case-insensitively against the start of the secret.
   */
  prefixes: string[];
  /** parts of the secret kept verbatim in "random" mode (e.g. PEM armor lines) */
  preserve?: RegExp;
  /** gitleaks quirk: generic rules require at least one digit in the secret */
  requireDigit: boolean;
  category: Category;
  /** extra check on the found value; the finding is dropped when it returns false */
  validate?: (value: string) => boolean;
}
