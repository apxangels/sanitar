import { defineConfig } from "vitest/config";

// root project: tests for scripts/ (packages and apps have their own configs)
export default defineConfig({
  test: { include: ["scripts/**/*.test.ts"] },
});
