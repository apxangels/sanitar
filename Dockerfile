# syntax=docker/dockerfile:1

# ---- build: install, build, test, assemble a production-only bundle ----
FROM node:24 AS build
WORKDIR /src
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

# dependency layer (cached while manifests don't change)
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY packages/core/package.json packages/core/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# set --build-arg RUN_TESTS=false to skip
ARG RUN_TESTS=true
RUN if [ "$RUN_TESTS" = "true" ]; then pnpm test; fi

# server + its production deps (incl. @sanitar/core) as a standalone directory
RUN pnpm --filter @sanitar/server deploy --prod /out \
 && rm -f /out/pnpm-lock.yaml /out/pnpm-workspace.yaml \
 && cp -r apps/web/dist /out/public

# ---- runtime ----
FROM node:24-slim
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    WEB_ROOT=/app/public
WORKDIR /app
# files stay owned by root and are read-only for the app user
COPY --from=build /out /app
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
