/**
 * Personal data (PII): emails, phone numbers, card numbers and personal fields
 * in structured data (first_name, birth_date…). Category "pii", so callers can
 * switch them off with `pii: false`.
 *
 * Regexes alone can't find names or addresses in free text; we only catch them
 * when the field name says what they are.
 */
import { CODE_REFERENCES, PLACEHOLDER_VALUES, type CustomRuleDef } from "./custom.js";
import { Specificity, type Allowlist } from "./types.js";

/** Luhn checksum over the digits of `s`. */
export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function isCardNumber(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  // issuer ranges actually in use: 2 (Mir, MC 2-series), 3 (Amex, JCB, Diners), 4 (Visa), 5 (MC), 6 (Discover, UnionPay)
  if (!/^[2-6]/.test(digits)) return false;
  // unseparated runs of digits are often IDs; only accept the common 15/16-digit lengths there
  if (digits === value && digits.length !== 15 && digits.length !== 16) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  return luhnValid(digits);
}

function isPhoneNumber(value: string): boolean {
  const digits = value.replace(/\D/g, "").length;
  if (value.startsWith("+")) return digits >= 8 && digits <= 15;
  // without a country code we require formatting, so plain numbers (IDs, timestamps) don't match
  return digits >= 10 && digits <= 11 && /\D/.test(value);
}

/** Values in `first_name = user.first_name` or `dob: new Date(…)` are code, not data. */
const CODE_VALUES: Allowlist = {
  condition: "OR",
  regexTarget: "secret",
  regexes: [
    /^[a-z_$][\w$]*(?:\.[a-z_$][\w$]*)+$/i,
    /^(?:await|new|yield|typeof|function|require|import|lambda|const|let|var)$/,
    /^(?:[a-z]+_)*(?:first|last|middle|full|sur|given|family)_?name$|^(?:birth_?date|dob|phone|ssn)$/i,
  ],
  stopwords: [],
};

/** Field names whose value is personal data. The key must END with one of these. */
const PERSONAL_KEYS = [
  "first[_.-]?name",
  "last[_.-]?name",
  "middle[_.-]?name",
  "full[_.-]?name",
  "sur[_.-]?name",
  "given[_.-]?name",
  "family[_.-]?name",
  "patronymic",
  "birth[_.-]?date",
  "date[_.-]?of[_.-]?birth",
  "birth[_.-]?day",
  "dob",
  "passport(?:[_.-]?(?:number|no|num|series))?",
  "ssn",
  "snils",
  "phone(?:[_.-]?(?:number|no))?",
  "mobile(?:[_.-]?(?:phone|number))?",
  "msisdn",
].join("|");

export const piiRules: CustomRuleDef[] = [
  {
    id: "email",
    description: "Email address.",
    // Not preceded by `user:` — in `user:pass@host` the part after `:` is a
    // password (host-password / url-password handle it), unless it's `mailto:`.
    regex:
      /(?:(?<=mailto:)|(?<![\w.%+/-])(?<![\w.%+-]:))[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9_-])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-]|\.[a-z0-9])/gi,
    keywords: ["@"],
    specificity: Specificity.Contextual,
    category: "pii",
    allowlists: [
      {
        condition: "OR",
        regexTarget: "secret",
        regexes: [
          // git@github.com:org/repo — an SSH login, not a mailbox
          /^git@/i,
          // icon@2x.png, bundle@1x.js
          /\.(?:png|jpe?g|gif|svg|webp|avif|ico|js|mjs|cjs|ts|tsx|jsx|css|map|json|html?)$/i,
        ],
        stopwords: [],
      },
    ],
  },
  {
    id: "phone-number",
    description: "Phone number (international +…, Russian 8 (…), North American (…) …-…).",
    regex:
      /(?<![\w+.-])(?:\+(?:\d[ .()-]{0,2}){7,14}\d|8[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|\(\d{3}\) ?\d{3}[ .-]\d{4}|\d{3}[.-]\d{3}[.-]\d{4})(?![\w-]|\.\d)/g,
    keywords: [],
    specificity: Specificity.Contextual,
    category: "pii",
    validate: isPhoneNumber,
  },
  {
    id: "card-number",
    description: "Payment card number (passes the Luhn check).",
    regex: /(?<![\w.-])(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})(?![\w-]|[.,]\d)/g,
    keywords: [],
    specificity: Specificity.Specific,
    category: "pii",
    validate: isCardNumber,
  },
  {
    id: "personal-field",
    description: "Personal data in a named field (first_name, last_name, birth_date, passport, phone…).",
    // Same value syntax as password-assignment: quoted (may contain spaces) or a bare token.
    regex: new RegExp(
      String.raw`(?:^|[^\w.-])(?:[\w.-]{0,30}(?:${PERSONAL_KEYS}))["']?[ \t]*(?:=>|:=|=|:)[ \t]*(?:"([^"\r\n]{1,200})"|'([^'\r\n]{1,200})'|([^\s"'\x60,;=<>(){}[\]][^\s"'\x60,;<>(){}[\]]{0,199})(?=$|[\s,;"'\x60)\]}<>]))`,
      "gim",
    ),
    keywords: [
      "name",
      "patronymic",
      "birth",
      "dob",
      "passport",
      "ssn",
      "snils",
      "phone",
      "mobile",
      "msisdn",
    ],
    specificity: Specificity.Generic,
    category: "pii",
    allowlists: [PLACEHOLDER_VALUES, CODE_REFERENCES, CODE_VALUES],
  },
];
