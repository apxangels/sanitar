import { describe, expect, it } from "vitest";
import { sanitize, scan, preview, InputTooLargeError, MAX_INPUT_BYTES } from "../src/index.js";
import { fake } from "./helpers.js";

describe("modes", () => {
  const token = fake.githubPat();
  const text = `export GITHUB_TOKEN=${token}\necho done\n`;

  it("placeholder (default)", () => {
    const r = sanitize(text, { mode: "placeholder" });
    expect(r.text).toBe("export GITHUB_TOKEN=<secret>\necho done\n");
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.ruleId).toBe("github-pat");
  });

  it("placeholder with custom string and type", () => {
    expect(sanitize(text, { mode: "placeholder", placeholder: "***" }).text).toBe("export GITHUB_TOKEN=***\necho done\n");
    expect(sanitize(text, { mode: "placeholder", placeholderWithType: true }).text).toBe(
      "export GITHUB_TOKEN=<secret:github-pat>\necho done\n",
    );
    expect(sanitize(text, { mode: "placeholder", placeholder: "[REDACTED]", placeholderWithType: true }).text).toBe(
      "export GITHUB_TOKEN=[REDACTED:github-pat]\necho done\n",
    );
  });

  it("erase keeps the surroundings", () => {
    expect(sanitize(text, { mode: "erase" }).text).toBe("export GITHUB_TOKEN=\necho done\n");
  });

  it("random keeps length, character classes, separators and the known prefix", () => {
    const jwt = fake.jwt();
    const input = `token: ${token}\njwt=${jwt}\n`;
    const r = sanitize(input, { mode: "random" });
    const [l1, l2] = r.text.split("\n");
    const newToken = l1!.slice("token: ".length);
    const newJwt = l2!.slice("jwt=".length);

    expect(newToken).not.toBe(token);
    expect(newToken).toHaveLength(token.length);
    expect(newToken.startsWith("gh" + "p_")).toBe(true);
    expect(newJwt).not.toBe(jwt);
    expect(newJwt).toHaveLength(jwt.length);
    for (let i = 0; i < jwt.length; i++) {
      const a = jwt[i]!;
      const b = newJwt[i]!;
      if (/[a-z]/.test(a)) expect(b).toMatch(/[a-z]/);
      else if (/[A-Z]/.test(a)) expect(b).toMatch(/[A-Z]/);
      else if (/[0-9]/.test(a)) expect(b).toMatch(/[0-9]/);
      else expect(b).toBe(a); // dots, dashes, underscores stay in place
    }
  });

  it("random keeps PEM armor lines of a private key", () => {
    const key = fake.privateKey();
    const r = sanitize(`key:\n${key}\n`, { mode: "random" });
    const lines = r.text.split("\n");
    expect(lines[1]).toBe("-----BEGIN RSA PRIVATE" + " KEY-----");
    expect(lines[14]).toBe("-----END RSA PRIVATE" + " KEY-----");
    expect(r.text).not.toContain(key.split("\n")[1]);
  });

  it("rejects an unknown mode", () => {
    expect(() => sanitize("x", { mode: "nope" as never })).toThrow(/unknown mode/);
  });
});

describe("detection details", () => {
  it("secretGroup: only the value is replaced, not KEY=", () => {
    const pw = fake.password();
    const r = sanitize(`DB_PASSWORD=${pw}\nDB_USER=app\n`, { mode: "placeholder" });
    expect(r.text).toBe("DB_PASSWORD=<secret>\nDB_USER=app\n");
  });

  it("positions are offsets in the original text, with 1-based lines", () => {
    const a = fake.githubPat();
    const b = fake.awsKeyId();
    const text = `first line\nA=${a}\n\nB = "${b}"\n`;
    const { findings } = scan(text);
    expect(findings).toHaveLength(2);
    for (const f of findings) expect([a, b]).toContain(text.slice(f.start, f.end));
    expect(findings.map((f) => f.line)).toEqual([2, 4]);
    // sanitize reports the same positions (in the original, not the output)
    expect(sanitize(text, { mode: "placeholder", placeholder: "X" }).findings).toEqual(findings);
  });

  it("several secrets in one line", () => {
    const a = fake.githubPat();
    const b = fake.awsKeyId();
    const c = fake.slackBot();
    const r = sanitize(`tokens: ${a} ${b} ${c} end`, { mode: "placeholder" });
    expect(r.text).toBe("tokens: <secret> <secret> <secret> end");
    expect(r.findings.map((f) => f.ruleId)).toEqual(["github-pat", "aws-access-token", "slack-bot-token"]);
  });

  it("multi-line private key is replaced as one block", () => {
    const key = fake.privateKey("OPENSSH");
    const r = sanitize(`before\n${key}\nafter`, { mode: "placeholder" });
    expect(r.text).toBe("before\n<secret>\nafter");
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.line).toBe(2);
  });

  it("password in a URL", () => {
    const pw = fake.password();
    const r = sanitize(`DATABASE_URL=postgres://app:${pw}@db.internal:5432/main`, { mode: "placeholder" });
    expect(r.text).toBe("DATABASE_URL=postgres://app:<secret>@db.internal:5432/main");
  });

  it("password / secret in configs, quoted with spaces", () => {
    const r = sanitize(`password: "correct horse battery"\nclient_secret = '${fake.password()}'\n`, { mode: "placeholder" });
    expect(r.text).toBe(`password: "<secret>"\nclient_secret = '<secret>'\n`);
  });

  it("access keys and tokens in configs, even low-entropy ones without digits", () => {
    const text = [
      "    environment:",
      "      ROOT_ACCESS_KEY: someadmin",
      `      ROOT_SECRET_KEY: ${fake.password()}`,
      "      VGW_ADMIN_ORIGINS: \"*\"",
      `API_KEY="${fake.password()}"`,
      `token=${fake.password()}`,
      `aws_access_key_id = ${fake.password()}`,
    ].join("\n");
    const r = sanitize(text, { mode: "placeholder" });
    expect(r.text).toBe(
      [
        "    environment:",
        "      ROOT_ACCESS_KEY: <secret>",
        "      ROOT_SECRET_KEY: <secret>",
        "      VGW_ADMIN_ORIGINS: \"*\"",
        'API_KEY="<secret>"',
        "token=<secret>",
        "aws_access_key_id = <secret>",
      ].join("\n"),
    );
  });

  it("key/token-like names that don't hold credentials are left alone", () => {
    const text = [
      "max_tokens: 4096",
      "token_type: bearer",
      "PRIVATE_KEY_PATH=/etc/ssl/key.pem",
      "api_key_name: X-Api-Key",
      "primary_key: id",
      "token?: string;",
      "const token = getToken();",
      "token = response.data.token",
      "apiKey: apiKey,",
      "API_KEY=${API_KEY}",
      "token: {{ .Values.token }}",
    ].join("\n");
    expect(scan(text).findings).toEqual([]);
  });

  it("Authorization header", () => {
    const tok = fake.password() + fake.password();
    const r = sanitize(`Authorization: Bearer ${tok}`, { mode: "placeholder" });
    expect(r.text).toBe("Authorization: Bearer <secret>");
  });

  it("placeholders and code references are not secrets", () => {
    const text = [
      "password=${DB_PASSWORD}",
      "password: <your password>",
      "password = self.password",
      "secret: {{ .Values.secret }}",
      "password_length: 12",
      "Authorization: Bearer $TOKEN",
      "url: https://user:${PASS}@host/",
    ].join("\n");
    expect(scan(text).findings).toEqual([]);
  });

  it("overlapping findings merge into one, the specific rule wins over generic", () => {
    const jwt = fake.jwt();
    const r = sanitize(`Authorization: Bearer ${jwt}`, { mode: "placeholder", placeholderWithType: true });
    expect(r.text).toBe("Authorization: Bearer <secret:jwt>");
    expect(r.findings).toHaveLength(1);
  });

  it("preview never shows more than 4 chars", () => {
    expect(preview("short")).toBe("…");
    expect(preview("abcdefghijklmnop")).toBe("abcd…");
    const { findings } = scan(`x=${fake.githubPat()}`);
    expect(findings[0]!.preview).toBe("gh" + "p_…");
  });
});

describe("edge cases", () => {
  it("empty text", () => {
    expect(sanitize("", { mode: "placeholder" })).toEqual({ text: "", findings: [], excluded: [], errors: [] });
  });

  it("text without secrets is returned byte for byte", () => {
    const text = "Hello\r\nworld\t🙂 — ünïcödé\n\n  const x = 42;\r\n";
    const r = sanitize(text, { mode: "random" });
    expect(r.text).toBe(text);
    expect(r.findings).toEqual([]);
  });

  it("idempotent: sanitized output has no findings", () => {
    const text = `A=${fake.githubPat()}\npassword: "${fake.password()}"\n${fake.privateKey()}`;
    const once = sanitize(text, { mode: "placeholder" }).text;
    expect(scan(once).findings).toEqual([]);
  });

  it("rejects input over the size limit", () => {
    const big = "a".repeat(MAX_INPUT_BYTES + 1);
    expect(() => scan(big)).toThrow(InputTooLargeError);
    // multi-byte chars count as UTF-8 bytes
    expect(() => scan("я".repeat(MAX_INPUT_BYTES / 2 + 1))).toThrow(InputTooLargeError);
    expect(() => scan("a".repeat(MAX_INPUT_BYTES))).not.toThrow();
  });
});
