# web4 deployment

This deployment is isolated under `/home/ubuntu/fy/service` and uses the
`rn-foundation-*` Docker names. It does not install host-level Node, pnpm, or
Nginx.

1. Edit `.env` and replace every `CHANGE_ME_MYSQL_*` value. Connection
   behavior is configurable with `MYSQL_CHARSET`, `MYSQL_TIMEZONE`, and
   `MYSQL_PARSE_TIME`.
2. Set `ADMIN_USERNAME` and a scrypt `ADMIN_PASSWORD_HASH`. The browser never receives `ADMIN_API_KEY`;
   that optional value is only for controlled automation.
3. Set `ADMIN_COOKIE_SECURE=true` after the console is served over HTTPS.
4. Run `./start.sh`.
5. Check the deployment with `./status.sh`.

Endpoints after a successful start:

- RN-Server: `http://15.235.225.217:3100`
- RN-Admin: `http://15.235.225.217:3180`

`./stop.sh` removes only this Compose project's containers and network. MySQL
data is external and is not deleted by the script.

## GitHub Actions deployment

The `main` branch workflow validates the repository, uploads an isolated
staging directory, acquires `/home/ubuntu/fy/service/.deploy.lock`, rebuilds
only its own Compose service, checks container health, and restores the prior
source on failure. Configure these repository secrets in both repositories:

- `WEB4_HOST`
- `WEB4_USER`
- `WEB4_SSH_KEY`
- `WEB4_KNOWN_HOSTS`

Then set the repository variable `WEB4_DEPLOY_ENABLED=true`. Until it is set,
validation still runs on every push to `main`, while deployment is safely
skipped.

The production `.env` remains only on web4 and is never uploaded from GitHub.
