import { existsSync } from "node:fs";
import type { Writable } from "node:stream";
import fastifyStatic from "@fastify/static";
import { InputTooLargeError, MAX_INPUT_BYTES, MODES, sanitize, scan, type Mode } from "@sanitar/core";
import Fastify, { LogController, type FastifyError } from "fastify";

export interface AppOptions {
  /** directory with the built web app; static serving is skipped if missing */
  webRoot?: string;
  logLevel?: string;
  /** where logs go (tests capture it); default stdout */
  logStream?: Writable;
}

const CSP = [
  "default-src 'self'",
  "connect-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
].join("; ");

const MAX_EXCLUSIONS = 500;
const MAX_EXCLUSION_LENGTH = 2000;

const exclusionsSchema = {
  type: "array",
  maxItems: MAX_EXCLUSIONS,
  items: { type: "string", maxLength: MAX_EXCLUSION_LENGTH },
} as const;

const sanitizeSchema = {
  body: {
    type: "object",
    required: ["text", "mode"],
    additionalProperties: false,
    properties: {
      text: { type: "string" },
      mode: { type: "string", enum: [...MODES] },
      placeholder: { type: "string", maxLength: 200 },
      placeholderWithType: { type: "boolean" },
      exclusions: exclusionsSchema,
      pii: { type: "boolean" },
    },
  },
} as const;

const scanSchema = {
  body: {
    type: "object",
    required: ["text"],
    additionalProperties: false,
    properties: {
      text: { type: "string" },
      exclusions: exclusionsSchema,
      pii: { type: "boolean" },
    },
  },
} as const;

interface SanitizeBody {
  text: string;
  mode: Mode;
  placeholder?: string;
  placeholderWithType?: boolean;
  exclusions?: string[];
  pii?: boolean;
}

interface ScanBody {
  text: string;
  exclusions?: string[];
  pii?: boolean;
}

/** path without query string: queries could carry anything */
function pathOf(url: string): string {
  const q = url.indexOf("?");
  return q === -1 ? url : url.slice(0, q);
}

const PUBLIC_MESSAGES: Record<number, string> = {
  400: "bad request",
  404: "not found",
  405: "method not allowed",
  413: "payload too large",
  415: "unsupported media type",
  500: "internal error",
};

export async function buildApp(opts: AppOptions = {}) {
  const app = Fastify({
    bodyLimit: MAX_INPUT_BYTES,
    // Request logging is done by hand below: method, path, status, time. Never bodies.
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: opts.logLevel ?? "info",
      ...(opts.logStream ? { stream: opts.logStream } : {}),
      serializers: {
        req: (req) => ({ method: req.method, path: pathOf(req.url) }),
        res: (res) => ({ statusCode: res.statusCode }),
        // error messages can contain request data (e.g. JSON.parse quotes the input)
        err: (err: FastifyError) => ({ type: err.name, code: err.code, message: "[redacted]", stack: "" }),
      },
    },
  });

  app.addHook("onSend", async (req, reply) => {
    reply.header("Content-Security-Policy", CSP);
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
    reply.header("Cross-Origin-Resource-Policy", "same-origin");
    if (req.url.startsWith("/api/")) reply.header("Cache-Control", "no-store");
  });

  app.addHook("onResponse", async (req, reply) => {
    req.log.info(
      { method: req.method, path: pathOf(req.url), status: reply.statusCode, ms: Math.round(reply.elapsedTime) },
      "request",
    );
  });

  app.setErrorHandler((err: FastifyError, req, reply) => {
    let status = err.statusCode && err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 500;
    if (err instanceof InputTooLargeError) status = 413;
    // Only the error type/code is logged, never err.message (see serializers.err).
    if (status >= 500) req.log.error({ err }, "request failed");
    // Schema validation messages describe the schema, not the values, so they are safe to return.
    const message = err.validation ? `invalid request: ${err.message}` : (PUBLIC_MESSAGES[status] ?? "error");
    void reply.status(status).send({ error: message });
  });

  app.setNotFoundHandler((_req, reply) => {
    void reply.status(404).send({ error: PUBLIC_MESSAGES[404] });
  });

  app.get("/healthz", async () => ({ status: "ok" }));

  app.post<{ Body: SanitizeBody }>("/api/sanitize", { schema: sanitizeSchema }, async (req) => {
    const { text, ...options } = req.body;
    return sanitize(text, options);
  });

  app.post<{ Body: ScanBody }>("/api/scan", { schema: scanSchema }, async (req) => {
    return scan(req.body.text, { exclusions: req.body.exclusions ?? [], pii: req.body.pii ?? true });
  });

  if (opts.webRoot && existsSync(opts.webRoot)) {
    await app.register(fastifyStatic, {
      root: opts.webRoot,
      index: "index.html",
      cacheControl: false, // set below
      setHeaders(res, filePath) {
        // Vite assets have content hashes in their names
        if (/[\\/]assets[\\/]/.test(filePath)) res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
        else res.setHeader("Cache-Control", "no-cache");
      },
    });
  } else if (opts.webRoot) {
    app.log.warn({ webRoot: opts.webRoot }, "web root not found, serving API only");
  }

  return app;
}
