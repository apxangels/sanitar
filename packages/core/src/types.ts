export type Mode = "placeholder" | "erase" | "random";

export interface SanitizeOptions {
  mode: Mode;
  /** default "<secret>" */
  placeholder?: string;
  /** "<secret:aws-access-token>"; default false */
  placeholderWithType?: boolean;
  /** user regexes (sources, optionally "/pattern/flags") */
  exclusions?: string[];
}

export interface ScanOptions {
  exclusions?: string[];
}

export interface Finding {
  ruleId: string;
  description: string;
  /** offset of the secret in the original text (UTF-16 code units) */
  start: number;
  end: number;
  /** 1-based */
  line: number;
  /** masked value: first 4 chars + "…", or just "…" for short secrets */
  preview: string;
}

export interface ExclusionError {
  /** 1-based index in the exclusions list */
  line: number;
  pattern: string;
  message: string;
}

export interface ScanResult {
  findings: Finding[];
  excluded: Finding[];
  errors: ExclusionError[];
}

export interface SanitizeResult extends ScanResult {
  text: string;
}
