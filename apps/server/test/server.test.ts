import { Writable } from "node:stream";
import { MAX_INPUT_BYTES, sanitize } from "@sanitar/core";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";

const rand = (n: number) => {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => a[b % a.length]).join("");
};
const fakeToken = () => "gh" + "p_" + rand(36);

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: Buffer, _enc: string, cb: () => void) {
    this.chunks.push(chunk.toString());
    cb();
  }
  get text() {
    return this.chunks.join("");
  }
}

let logs: Capture;
const apps: Awaited<ReturnType<typeof buildApp>>[] = [];
async function app() {
  logs = new Capture();
  const a = await buildApp({ logStream: logs, logLevel: "debug" });
  apps.push(a);
  return a;
}
afterEach(async () => {
  await Promise.all(apps.splice(0).map((a) => a.close()));
});

describe("API", () => {
  it("GET /healthz", async () => {
    const res = await (await app()).inject({ method: "GET", url: "/healthz" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });

  it("POST /api/sanitize returns the same as core sanitize()", async () => {
    const token = fakeToken();
    const body = { text: `TOKEN=${token}\n`, mode: "placeholder", placeholderWithType: true, exclusions: ["(bad"] };
    const res = await (await app()).inject({ method: "POST", url: "/api/sanitize", payload: body });
    expect(res.statusCode).toBe(200);
    const json = res.json();
    expect(json).toEqual(sanitize(body.text, { mode: "placeholder", placeholderWithType: true, exclusions: ["(bad"] }));
    expect(json.text).toBe("TOKEN=<secret:github-pat>\n");
    expect(json.errors).toHaveLength(1);
    // the response never contains the secret itself
    expect(res.body).not.toContain(token);
  });

  it("POST /api/scan returns findings only", async () => {
    const res = await (await app()).inject({ method: "POST", url: "/api/scan", payload: { text: `x=${fakeToken()}` } });
    expect(res.statusCode).toBe(200);
    expect(Object.keys(res.json()).sort()).toEqual(["errors", "excluded", "findings"]);
    expect(res.json().findings).toHaveLength(1);
  });

  it("validates the body", async () => {
    const a = await app();
    expect((await a.inject({ method: "POST", url: "/api/sanitize", payload: { text: "x", mode: "nope" } })).statusCode).toBe(400);
    expect((await a.inject({ method: "POST", url: "/api/sanitize", payload: { mode: "erase" } })).statusCode).toBe(400);
  });

  it("413 on a body over 1 MiB", async () => {
    const res = await (await app()).inject({
      method: "POST",
      url: "/api/sanitize",
      payload: { text: "a".repeat(MAX_INPUT_BYTES + 10), mode: "erase" },
    });
    expect(res.statusCode).toBe(413);
  });

  it("security headers; no-store on /api", async () => {
    const a = await app();
    const res = await a.inject({ method: "POST", url: "/api/scan", payload: { text: "hello" } });
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(res.headers["content-security-policy"]).not.toMatch(/unsafe-/);
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["cache-control"]).toBe("no-store");
    const health = await a.inject({ method: "GET", url: "/healthz" });
    expect(health.headers["cache-control"]).toBeUndefined();
  });
});

describe("logging", () => {
  it("logs method, path, status and time — never bodies", async () => {
    const token = fakeToken();
    const a = await app();
    await a.inject({ method: "POST", url: "/api/sanitize?x=1", payload: { text: `TOKEN=${token}`, mode: "erase" } });
    const lines = logs.text.trim().split("\n").map((l) => JSON.parse(l));
    const req = lines.find((l) => l.msg === "request");
    expect(req).toMatchObject({ method: "POST", path: "/api/sanitize", status: 200 });
    expect(typeof req.ms).toBe("number");
    expect(logs.text).not.toContain(token);
    expect(logs.text).not.toContain("x=1");
  });

  it("malformed JSON with a secret doesn't leak into logs or the response", async () => {
    const token = fakeToken();
    const a = await app();
    const res = await a.inject({
      method: "POST",
      url: "/api/sanitize",
      headers: { "content-type": "application/json" },
      payload: `{"text": "${token}" oops`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.body).not.toContain(token);
    expect(logs.text).not.toContain(token);
    expect(logs.text).not.toContain("oops");
  });

  it("errors in oversized/invalid requests don't leak either", async () => {
    const token = fakeToken();
    const a = await app();
    await a.inject({ method: "POST", url: "/api/sanitize", payload: { text: token, mode: token } });
    await a.inject({
      method: "POST",
      url: "/api/sanitize",
      payload: { text: token + "a".repeat(MAX_INPUT_BYTES), mode: "erase" },
    });
    expect(logs.text).not.toContain(token);
  });
});
