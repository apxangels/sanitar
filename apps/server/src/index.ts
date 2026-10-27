import { fileURLToPath } from "node:url";
import { buildApp } from "./app.js";

const host = process.env.HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? 8080);
const webRoot = process.env.WEB_ROOT ?? fileURLToPath(new URL("../../web/dist", import.meta.url));

const app = await buildApp({ webRoot, logLevel: process.env.LOG_LEVEL ?? "info" });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    app.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  });
}

try {
  await app.listen({ host, port });
} catch (err) {
  app.log.error({ err }, "failed to start");
  process.exit(1);
}
