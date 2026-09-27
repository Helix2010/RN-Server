# web4 部署（已退役）

> **2026-09-12 起不再是生产环境。** 生产迁到 amos，见 `deploy/amos/README.md`
> 与 ADR-0015。web4 上四个容器已停止并移除，`.env` 及其六份历史备份已用
> `shred` 覆写删除——**照本文操作前要先重建 `.env`**，值可以从 amos 的
> `/etc/rn-foundation.env` 取。
>
> 本文保留有两个用处：一是回滚时按它重建 Compose 部署，二是它记录了 Docker +
> Caddy 那套方案的完整细节，amos 那套在很多地方是对照着它做的。
>
> 回滚路径：从 amos 重建 `.env` → `./start.sh` → 把 Cloudflare 上
> `api.anyfun.win` / `console.anyfun.win` 的 A 记录改回 web4 的 IP。数据在共用的
> 数据库里，不需要迁移。

This deployment is isolated under `/home/ubuntu/fy/service` and uses the
`rn-foundation-*` Docker names. It does not install host-level Node, pnpm, or
Nginx.

1. Edit `.env` and fill in `MYSQL_DSN` — one line in go-sql-driver form,
   `user:password@tcp(host:port)/database?params`. Since 2026-09-13 the old
   eleven `MYSQL_HOST`/`MYSQL_CHARSET`/… keys are no longer read; leaving them
   in place without a `MYSQL_DSN` makes the server refuse to start and name
   them. Pool size, startup retries and the query timeout stay as their own
   `MYSQL_*` keys — the driver does not know about those. The configured
   database must already exist; RN-Server never runs `CREATE DATABASE` during
   application startup.
2. The console has no password account any more: console users sign in through unified login, and their
   accounts are written into `tenant_admin_accounts` by the external system (RN-Server design
   `console-accounts-external-maintenance-2026-09-27`). The browser never receives `ADMIN_API_KEY`;
   that optional value is only for controlled automation.
3. Set `PUBLIC_BASE_DOMAIN` and `PUBLIC_CONSOLE_DOMAIN`, point `PUBLIC_SERVER_URL` and
   `CORS_ORIGINS` to their HTTPS origins, set `PUBLIC_API_DOMAIN`, and keep
   `ADMIN_COOKIE_SECURE=true`. Store a Cloudflare API token with
   only Zone Read and DNS Edit access to the target zone in `CLOUDFLARE_API_TOKEN`.
4. Production defaults to `MYSQL_AUTO_MIGRATE=false`. `start.sh` runs the
   forward-only `migrate` command before starting containers; enable startup
   migration only for an isolated initialization environment, then disable it again.
5. Generate `STORAGE_MASTER_KEY` with `openssl rand -base64 32`. It encrypts tenant
   S3 credentials in MySQL and must be backed up. Losing or directly replacing it
   makes stored credentials unreadable.
6. Push credentials live only in this `.env` (the compose file passes them
   through; nothing is read from files at runtime). Keep the originals in
   `~/fy/secrets/<tenant>/` on this host as the archive and derive `.env` from
   them:
   - `FCM_PROJECT_ID=<firebase project id>`
   - `FCM_SERVICE_ACCOUNT_JSON=$(base64 -w0 firebase-service-account.json)`
   - `PUSH_DISPATCH_ENABLED=true` once the credentials are in place
   - iOS later: `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_PRIVATE_KEY` (base64 `.p8`),
     `APNS_BUNDLE_ID`, `APNS_ENVIRONMENT`
   Apply with `docker compose --env-file .env -f compose.yaml up -d --no-deps server`
   and confirm the log has no `push dispatcher initialization failed`.
7. Run `./start.sh`.
8. Check the deployment with `./status.sh`.

The isolated `rn-foundation-gateway` Caddy container binds ports 80/443, routes
the admin UI and Go API by hostname, and uses Cloudflare DNS-01 to automatically
obtain and renew a `*.anyfun.win` certificate without disabling the Cloudflare
proxy. Unknown subdomains return 404 until an explicit upstream mapping is added.
Its ACME state is stored in the
`rn-foundation-caddy-data` named volume and is not removed by source deployments.

Public endpoints after a successful start:

- HTTPS console: `https://console.anyfun.win`
- HTTPS API: `https://api.anyfun.win`

The raw service ports are loopback-only diagnostics on web4 and are not
reachable from the public network:

- RN-Server: `http://127.0.0.1:3100`
- RN-Admin: `http://127.0.0.1:3180`

External traffic must enter through the Caddy gateway on ports 80/443. This
keeps session cookies, CORS and hostname routing on the configured HTTPS
origins instead of exposing the application containers directly.

`./stop.sh` removes only this Compose project's containers and network. MySQL
data is external and is not deleted by the script.

## GitHub Actions deployment（已删除）

`deploy-web4.yml` 已从两个仓库移除，换成了 `deploy-amos.yml`。留着它的风险是有人
把 `WEB4_DEPLOY_ENABLED` 打开，就会把代码发到一台不再是生产环境的机器上，而它连
的还是同一个数据库。

`WEB4_HOST` / `WEB4_USER` / `WEB4_SSH_KEY` / `WEB4_KNOWN_HOSTS` 这几个 secret 和
`WEB4_DEPLOY_ENABLED` 变量已经没有任何 workflow 会读，可以在 GitHub 上删掉。

要回滚到 web4，从 git 历史里取回这个 workflow（最后一版在移除 amos workflow 的
那次提交之前），或者直接用本文上面的手工步骤——回滚是低频操作，不值得为它一直
留着一条能自动往退役机器上发版的路。

The production `.env` remains only on web4 and is never uploaded from GitHub.
