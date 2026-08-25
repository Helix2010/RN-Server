FROM caddy:2.10.2-builder-alpine AS builder

RUN xcaddy build \
  --with github.com/caddy-dns/cloudflare@v0.2.4

FROM caddy:2.10.2-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
