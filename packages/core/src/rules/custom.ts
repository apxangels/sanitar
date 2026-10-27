/**
 * Our own rules on top of gitleaks. They are tuned for pasted logs/configs
 * rather than git history, so they are a bit more aggressive than gitleaks.
 */
import { Specificity, type Allowlist } from "./types.js";

export interface CustomRuleDef {
  id: string;
  description: string;
  regex: RegExp;
  secretGroup?: number;
  entropy?: number;
  keywords: string[];
  allowlists?: Allowlist[];
  specificity: Specificity;
  prefixes?: string[];
  preserve?: RegExp;
}

/** Values that are obviously placeholders/templating, not secrets. */
const PLACEHOLDER_VALUES: Allowlist = {
  condition: "OR",
  regexTarget: "secret",
  regexes: [
    // ${VAR}, $VAR, $(cmd), %VAR%, {{ tmpl }}, <placeholder>, [placeholder], ***, xxx, ...
    /^(?:\$\{?[\w.:-]+\}?|\$\([^)]*\)|%\w+%|\{\{.*\}\}|<[^>]*>|\[[^\]]*\]|\*+|x+|\.{2,}|…)$/i,
    /^(?:true|false|null|nil|none|undefined|empty|required|optional|string|str|bool|boolean|int|integer|number|any|object|text|varchar|password|passwd|pass|pwd|secret|changeme|change_?me|example|sample|dummy|test|redacted|hidden|masked|removed|your[\w-]*|enter[\w-]*|<secret>)$/i,
  ],
  stopwords: [],
};

/** Values that are references to variables/fields in code, e.g. `password = self.password`. */
const CODE_REFERENCES: Allowlist = {
  condition: "OR",
  regexTarget: "secret",
  regexes: [
    /^(?:self|this|ctx|context|config|cfg|conf|settings|options|opts|params|args|argv|env|process\.env|os\.environ|request|req|res|data|user|form|props|state|values|input|credentials|creds|secrets|vault|getenv)[.[]/i,
    /(?:pass(?:word|wd)?|pwd|secret|passphrase)$/i,
  ],
  stopwords: [],
};

/** Key names that mention a password but don't hold one (password_length, secretName…). */
const NON_SECRET_KEYS: Allowlist = {
  condition: "OR",
  regexTarget: "match",
  regexes: [
    /(?:password|passwd|pwd|secret|passphrase)[\w.-]*?(?:length|len|size|name|names|hash|hashed|policy|reset|file|path|dir|id|ids|type|ref|field|label|prompt|placeholder|hint|regex|pattern|rule|rules|expiry|expires|expiration|age|count|strength|manager|provider|store|arn|version|enabled|required|confirm|confirmation|changed|updated|forgot|ttl|timeout|format|mode|visible|toggle)["']?[ \t]*(?:=>|:=|=|:)/i,
  ],
  stopwords: [],
};

export const customRules: CustomRuleDef[] = [
  {
    id: "private-key-block",
    description: "Private key block (PEM / OpenSSH / PGP), whole block including BEGIN/END lines.",
    regex:
      /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g,
    keywords: ["-----begin"],
    specificity: Specificity.Specific,
    preserve: /-----(?:BEGIN|END)[ A-Z0-9_-]{0,100}-----/g,
  },
  {
    id: "url-password",
    description: "Password embedded in a URL (scheme://user:password@host).",
    regex: /\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\/\/[^\s:@/?#'"<>]{0,128}:([^\s@/?#'"<>]{1,256})@[\w[.-]/g,
    secretGroup: 1,
    keywords: ["://"],
    specificity: Specificity.Contextual,
    allowlists: [PLACEHOLDER_VALUES],
  },
  {
    id: "authorization-header",
    description: "Credentials in an Authorization header (Bearer / Basic / token).",
    regex: /\bauthorization["']?[ \t]*[:=][ \t]*["']?(?:bearer|basic|token)[ \t]+([A-Za-z0-9\-._~+/]{8,}=*)/gi,
    secretGroup: 1,
    keywords: ["authorization"],
    specificity: Specificity.Contextual,
    allowlists: [PLACEHOLDER_VALUES],
  },
  {
    id: "bearer-token",
    description: "Bearer token.",
    regex: /\bbearer[ \t]+([A-Za-z0-9\-._~+/]{20,}=*)/gi,
    secretGroup: 1,
    entropy: 3,
    keywords: ["bearer"],
    specificity: Specificity.Contextual,
    allowlists: [PLACEHOLDER_VALUES],
  },
  {
    id: "password-assignment",
    description: "Password or secret assigned in a config, .env file or code (password=, passwd:, secret:).",
    // key (optionally prefixed/suffixed, e.g. DB_PASSWORD, client_secret) → separator → value.
    // The value is either quoted (may contain spaces) or a bare token that ends at
    // whitespace/punctuation, so `password = getPassword()` doesn't match.
    regex:
      /(?:^|[^\w.-])(?:[\w.-]{0,40}(?:password|passwd|passphrase|pwd|secret)[\w.-]{0,30})["']?[ \t]*(?:=>|:=|=|:)[ \t]*(?:"([^"\r\n]{1,200})"|'([^'\r\n]{1,200})'|([^\s"'`,;=<>(){}[\]][^\s"'`,;<>(){}[\]]{0,199})(?=$|[\s,;"'`)\]}<>]))/gim,
    keywords: ["pass", "pwd", "secret"],
    specificity: Specificity.Generic,
    allowlists: [PLACEHOLDER_VALUES, CODE_REFERENCES, NON_SECRET_KEYS],
  },
  {
    id: "credential-assignment",
    description: "Access key, API key or token assigned in a config, .env file or code (ACCESS_KEY=, api_key:, token=).",
    // Same value syntax as password-assignment. The key name must END with one of
    // the credential words, so max_tokens, token_type, PRIVATE_KEY_PATH,
    // api_key_name, primary_key etc. don't match. Access key IDs are included on
    // purpose: in pasted configs they are usually a login that shouldn't leak either.
    regex:
      /(?:^|[^\w.-])(?:[\w.-]{0,40}(?:access[_.-]?key(?:[_.-]?id)?|api[_.-]?key|app[_.-]?key|auth[_.-]?key|(?:root|master|admin|private|signing|encryption|license|account|service|client|consumer)[_.-]?key|token|credentials?))["']?[ \t]*(?:=>|:=|=|:)[ \t]*(?:"([^"\r\n]{1,200})"|'([^'\r\n]{1,200})'|([^\s"'`,;=<>(){}[\]][^\s"'`,;<>(){}[\]]{0,199})(?=$|[\s,;"'`)\]}<>]))/gim,
    keywords: ["key", "token", "credential"],
    specificity: Specificity.Generic,
    allowlists: [
      PLACEHOLDER_VALUES,
      CODE_REFERENCES,
      {
        condition: "OR",
        regexTarget: "secret",
        regexes: [
          // `token = token`, `apiKey: accessKey` — a variable name, not a value
          /^[a-z_][\w]*(?:key|token|credentials?)$/i,
          // `token = response.data.token`
          /^[a-z_$][\w$]*(?:\.[a-z_$][\w$]*)+$/i,
          // `token: 4096` in limits/usage stats, `key: 1`
          /^\d{1,6}$/,
          // `const token = await fetchToken()`
          /^(?:await|new|yield|typeof|async|function|require|import|lambda|fn|func|def|var|let|const|static|readonly|public|private|protected)$/,
        ],
        stopwords: [],
      },
    ],
  },
];
