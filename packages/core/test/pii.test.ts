import { describe, expect, it } from "vitest";
import { sanitize, scan } from "../src/index.js";
import { luhnValid } from "../src/rules/pii.js";

/** A Luhn-valid card number with the given prefix and length, generated at runtime. */
function cardNumber(prefix: string, length = 16): string {
  let body = prefix;
  while (body.length < length - 1) body += String(Math.floor(Math.random() * 10));
  for (let check = 0; check <= 9; check++) if (luhnValid(body + check)) return body + check;
  throw new Error("unreachable");
}

const ids = (text: string, pii = true) => scan(text, { pii }).findings.map((f) => f.ruleId);
const clean = (text: string) => sanitize(text, { mode: "placeholder" }).text;

describe("pii: emails", () => {
  it("finds emails", () => {
    expect(clean("contact ivan.petrov@example.com or <anna+news@mail.example.org>")).toBe(
      "contact <secret> or <<secret>>",
    );
    expect(clean("mailto:john@example.com")).toBe("mailto:<secret>");
  });

  it("leaves look-alikes alone", () => {
    const text = [
      "git clone git@github.com:org/repo.git",
      "background: url(icon@2x.png)",
      "npm i @scope/pkg@1.2.3 lodash@4.17.21",
      "ssh deploy@192.168.100.1",
      "bbs@bbs:~$ ls",
    ].join("\n");
    expect(ids(text)).toEqual([]);
  });

  it("in user:pass@host the password rule wins, the host stays", () => {
    expect(clean("ssh deploy:hunter2x@build-01.internal")).toBe("ssh deploy:<secret>@build-01.internal");
  });
});

describe("pii: phone numbers", () => {
  it("finds phones in common formats", () => {
    const phones = [
      "+7 (999) 123-45-67",
      "+79991234567",
      "+1 (555) 019-2834",
      "+44 20 7946 0958",
      "+49 30 1234567",
      "8 (999) 123-45-67",
      "8-999-123-45-67",
      "(555) 123-4567",
      "555-123-4567",
      "555.123.4567",
    ];
    for (const p of phones) expect(ids(`tel: ${p}, ok`), p).toEqual(["phone-number"]);
  });

  it("doesn't take dates, versions, IPs, IDs or timestamps for phones", () => {
    const text = [
      "2026-10-27T10:15:30Z",
      "1992-05-14",
      "version 10.2.3, build 20261027",
      "ip 192.168.100.109:7070",
      "uuid 550e8400-e29b-41d4-a716-446655440000",
      "ts=1761560130 id=89991234567 order 12345678",
      "balance: 15250.00",
      "x+12345678",
    ].join("\n");
    expect(ids(text)).toEqual([]);
  });
});

describe("pii: card numbers", () => {
  it("finds Luhn-valid card numbers, separated or not", () => {
    const visa = cardNumber("4");
    const mc = cardNumber("51");
    const amex = cardNumber("37", 15);
    const grouped = `${visa.slice(0, 4)} ${visa.slice(4, 8)} ${visa.slice(8, 12)} ${visa.slice(12)}`;
    const dashed = `${mc.slice(0, 4)}-${mc.slice(4, 8)}-${mc.slice(8, 12)}-${mc.slice(12)}`;
    const text = `card ${grouped}\ncard ${dashed}\ncard ${amex}\n`;
    expect(clean(text)).toBe("card <secret>\ncard <secret>\ncard <secret>\n");
  });

  it("ignores masked cards, Luhn failures and numbers that aren't cards", () => {
    const valid = cardNumber("4");
    const broken = valid.slice(0, -1) + String((Number(valid.at(-1)) + 1) % 10);
    const text = [
      "card_mask: 4111-XXXX-XXXX-8824",
      `card: ${broken}`,
      "ts: 1761560130123",
      "id: 4444444444444444",
    ].join("\n");
    expect(ids(text)).toEqual([]);
  });
});

describe("pii: personal fields", () => {
  it("replaces values of personal fields in JSON, YAML and .env", () => {
    const text = [
      '"first_name": "Иван",',
      '"lastName": "Petrov",',
      "birth_date: 1992-05-14",
      "PASSPORT_NUMBER='4510 123456'",
      '"phone": "89991234567"',
    ].join("\n");
    expect(clean(text)).toBe(
      ['"first_name": "<secret>",', '"lastName": "<secret>",', "birth_date: <secret>", "PASSPORT_NUMBER='<secret>'", '"phone": "<secret>"'].join(
        "\n",
      ),
    );
  });

  it("leaves schemas and code alone", () => {
    const text = [
      'first_name = models.CharField(max_length=100)',
      '"last_name": {"type": "string"}',
      "first_name: string;",
      "full_name = user.full_name",
      '"birth_date": null',
      "filename: report.pdf",
      "phone_verified: true",
    ].join("\n");
    expect(ids(text)).toEqual([]);
  });
});

describe("pii option", () => {
  const text = `email: ivan.petrov@example.com\npassword: ${"hunter" + "2x" + "zz"}\n`;

  it("is on by default and findings carry the category", () => {
    const { findings } = scan(text);
    expect(findings.map((f) => [f.ruleId, f.category])).toEqual([
      ["email", "pii"],
      ["password-assignment", "secret"],
    ]);
  });

  it("pii: false finds only secrets", () => {
    expect(ids(text, false)).toEqual(["password-assignment"]);
    expect(sanitize(text, { mode: "placeholder", pii: false }).text).toBe(
      "email: ivan.petrov@example.com\npassword: <secret>\n",
    );
  });
});
