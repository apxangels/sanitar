# Sanitar

Finds secrets (API keys, tokens, private keys, passwords, connection strings) and personal data (emails, phone numbers, card numbers, names, birth dates) in text and replaces them. Copy a log, config or stack trace, run it through Sanitar, and paste the cleaned version into a chat, a ticket or an AI assistant.

**The text is processed right in your browser.** The page bundles the detection engine and never sends the text anywhere. The Content Security Policy sets `connect-src 'none'`, so the browser itself blocks any network request from the page; you can confirm it in DevTools → Network. The HTTP API on the server exists only for curl/CLI use.

## Running

### GitHub Pages

The web page is fully static, so it can be hosted on GitHub Pages. `.github/workflows/pages.yml` runs the tests, builds `apps/web` and deploys it on every push to `main`/`master`.

One-time setup: **Settings → Pages → Build and deployment → Source: GitHub Actions**. The site will be at `https://<user>.github.io/<repo>/`. Asset URLs are relative, so any repository name works.

GitHub Pages can't send custom headers, so the CSP is set with a `<meta>` tag. One limit follows from that: `frame-ancestors` doesn't work in `<meta>`, so a Pages copy can be embedded in a frame on another site. The Docker version sends the full set of headers.

### Docker

```bash
docker compose up --build        # http://localhost:8080
```

The service listens on `127.0.0.1` only. The container runs as a non-root user with a read-only filesystem and `cap_drop: ALL`. It needs no outbound access; `docker-compose.yml` has a commented-out example of an isolated network.

### Without Docker

Requires Node 24 and pnpm via corepack.

```bash
corepack enable
pnpm install
pnpm build
pnpm start                 # http://127.0.0.1:8080
pnpm dev                   # Vite on :5173 + server on :8080 with reload
pnpm test
pnpm import-rules          # update the gitleaks rules (see below)
```

## Replacement modes

| Mode | Before | After |
|---|---|---|
| `<secret>` (placeholder) | `GITHUB_TOKEN=ghp_…` | `GITHUB_TOKEN=<secret>` |
| `<secret>` + "include the secret type" | | `GITHUB_TOKEN=<secret:github-pat>` |
| erase | `KEY=abc…` | `KEY=` |
| random text | `ghp_Ab3…` | `ghp_Qx7…` |

- **Custom placeholder:** you can set your own, e.g. `[REDACTED]`. With the type included it becomes `[REDACTED:github-pat]`.
- **random:**
  - keeps the length and format: lowercase letters become lowercase letters, uppercase become uppercase, digits become digits;
  - `-_/+=.` stay where they are;
  - known prefixes (`ghp_`, `AKIA`, `xoxb-`…) are kept, so the secret's type is still visible;
  - private keys keep their `-----BEGIN/END … PRIVATE KEY-----` lines.
- **Only the secret is replaced, not its surroundings:** in `password = "x"` only `x` goes away.

## Exclusions

Exclusions are regular expressions (JavaScript syntax), one per line. Each one is tested against the **value of a found secret** with `test()`, so a partial match is enough. A secret that matches an exclusion stays in the text and is shown in a separate list.

```
^sk-test-            # test keys
^dev_                # development tokens
/^stage_/i           # flags go in /pattern/flags form
```

- A line without surrounding slashes is a pattern without flags. `/usr/bin` counts as a pattern too, because `bin` is not a valid set of flags.
- An invalid expression doesn't break processing. It is highlighted with its error message, and the other exclusions still apply.
- Empty lines are ignored.
- There are no comments: `#` above is only for explanation.

## Extra rules (`extraRules`)

The opposite of exclusions: your own regular expressions for things to **replace** that the built-in rules miss (an internal ID format, a specific email domain). Same format as exclusions: one per line, `/pattern/flags` allowed, invalid lines are reported in `ruleErrors` with their line number and skipped.

```
[\w.]+@corp\.example     # whole match is replaced
ticket=(SEC-\d+)          # with a capture group, only the group is replaced
```

Findings get the rule id `user-rule` (`<secret:user-rule>` with the type included). Exclusions apply to them too. Entropy checks and gitleaks allowlists don't: you asked for exactly this. Available on the web page (the **Also replace** field under the exclusions, saved with the other settings), in `@sanitar/core` (`SanitizeOptions.extraRules`) and in the HTTP API.

## HTTP API (Docker / server only)

```bash
curl -s -X POST localhost:8080/api/sanitize \
  -H 'content-type: application/json' \
  -d '{"text":"DB_PASSWORD=hunter22\n","mode":"placeholder","placeholderWithType":true}'
# {"text":"DB_PASSWORD=<secret:password-assignment>\n","findings":[{"ruleId":"password-assignment",…,"line":1,"preview":"…"}],"excluded":[],"errors":[],"ruleErrors":[]}

# findings only, no replacement
curl -s -X POST localhost:8080/api/scan -H 'content-type: application/json' -d '{"text":"…","exclusions":["^sk-test-"]}'

curl -s localhost:8080/healthz
```

**Request body:** `{ text, mode: "placeholder" | "erase" | "random", placeholder?, placeholderWithType?, exclusions?: string[], extraRules?: string[], pii?: boolean }`. `pii` (default `true`) also finds personal data; `/api/scan` accepts `pii` too.

**Response:** the same result as `sanitize()` in the UI.
- Each finding has a `category`: `"secret"` or `"pii"`.
- `start`/`end` are offsets in the original text, in UTF-16 code units, like JavaScript strings.
- The secret itself is never returned. Each finding has only a `preview`: the first 4 characters, or just `…` for short secrets.

**Limits:** 1 MiB of text (UTF-8) and 1 MiB of request body; anything larger gets `413`. Request and response bodies are never logged; the log has only the method, path, status and duration.

## How detection works

- **gitleaks rules.**
  - Rules come from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT; the version is pinned in `scripts/import-gitleaks-rules.ts`).
  - The import script converts Go RE2 into JS RegExp (`(?i)` mid-pattern, `(?-i:…)`, `(?s:.)`, `\z`, POSIX classes, `[^]]`…) and writes `packages/core/src/rules/gitleaks.json`.
  - The JSON is committed, so the build never goes to the network.
  - Rules that can't be converted are reported and skipped. One is skipped at the moment: `pkcs12-file`, which only checks file names.
- **Own rules** (`packages/core/src/rules/custom.ts`):
  - whole private key blocks (multi-line);
  - passwords in URLs (`scheme://user:PASSWORD@host`);
  - `password=` / `passwd:` / `secret:` in configs and `.env`;
  - `ACCESS_KEY=` / `api_key:` / `token=` in configs and `.env`;
  - `Authorization: Bearer/Basic …`.
- **Personal data** (`packages/core/src/rules/pii.ts`, can be switched off in the UI or with `pii: false`):
  - emails;
  - phone numbers: any format with `+` and a country code, Russian `8 (999) 123-45-67`, North American `(555) 123-4567` / `555-123-4567`. Plain digit runs without `+` or separators are not treated as phones, so IDs and timestamps don't match;
  - card numbers that pass the Luhn check (masked ones like `4111-XXXX-XXXX-8824` are left alone);
  - values of personal fields by name: `first_name`, `lastName`, `full_name`, `birth_date`, `dob`, `passport`, `ssn`, `snils`, `phone`, `mobile`…
- **Pipeline:**
  1. keyword prefilter;
  2. regex;
  3. Shannon entropy threshold;
  4. gitleaks allowlists;
  5. user exclusions;
  6. overlap merging (a specific rule wins over a generic one).

## Limitations

- **Regexes and entropy only.** Detection is based on regular expressions and entropy. Keys are not checked for validity, and no service is contacted.
- **Misses are possible.** A secret with no recognizable format and no hint like `password=` next to it won't be found.
- **False positives are possible.** Random strings can look like tokens. Review the result before sending it.
- **Names and addresses in free text are not found.** Regexes can't tell "Ivan Petrov" from any other two words; they are only found when the field name says what they are (`"first_name": "Ivan"`).
- **File-path rules apply to all text.** Some gitleaks rules are tied to file names (`*.tf`, `*.yaml`, `nuget.config`). They apply to all text, because pasted text has no file name.
- **Size limit.** The maximum text size is 1 MiB.

## Layout

```
packages/core   engine: scan(), sanitize(). Plain TS with no DOM/Node APIs and no runtime dependencies
apps/web        the page (Vite + TS), imports core directly
apps/server     Fastify: static files + /api/sanitize, /api/scan, /healthz
scripts         gitleaks rule import
```

gitleaks attribution is in [NOTICE](NOTICE).
