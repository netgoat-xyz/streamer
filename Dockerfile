# syntax=docker/dockerfile:1

FROM oven/bun:1.4.4-alpine AS build
WORKDIR /app
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY server.ts ./
COPY models ./models
RUN bun build --compile --minify --sourcemap=none server.ts --outfile /out/stream-server

FROM alpine:3.21
LABEL org.opencontainers.image.description="Minimal hardened NetGoat stream server runtime" \
      org.opencontainers.image.base.name="alpine:3.21"
RUN apk add --no-cache ca-certificates libstdc++ libgcc \
  && adduser -D -H -s /sbin/nologin -u 10001 stream \
  && rm -rf /var/cache/apk/* /tmp/*
WORKDIR /app
COPY --from=build --chown=stream:stream /out/stream-server /app/stream-server
USER 10001:10001
EXPOSE 8787
ENV HOST=0.0.0.0 \
    PORT=8787 \
    SEED_FILE=/app/seed-data.json \
    LOG_LEVEL=info
HEALTHCHECK --interval=10s --timeout=3s --retries=10 --start-period=15s CMD wget -qO- --header="X-API-Key: ${API_KEY:-${DIAMOND_KEY:-}}" "http://127.0.0.1:${PORT:-8787}/health" >/dev/null || exit 1
ENTRYPOINT ["/app/stream-server"]
