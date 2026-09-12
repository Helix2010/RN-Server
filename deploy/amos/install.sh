#!/usr/bin/env bash
# 在 amos 上一次性装好目录、用户、systemd 与 nginx 站点。只跑一次，之后更新走
# deploy.sh。在 amos 上以能 sudo 的普通用户执行，同目录下要有本仓库 deploy/amos
# 的四个文件。
#
# 不装 Docker，也不装 Go：和打包机代理同一套规范，程序在 /opt，配置在 /etc 下 0600。
set -euo pipefail

cd "$(dirname "$0")"
for f in rn-foundation-server.service rn-foundation-indexer.service \
         rn-foundation.env.example nginx-rn-foundation.conf; do
  [ -f "$f" ] || { echo "缺少 $f" >&2; exit 1; }
done

echo "== 用户与目录 =="
# 系统账号，不给登录 shell、不建家目录：这个进程不需要家目录，也不该能被 su 过去
id rnfoundation >/dev/null 2>&1 || sudo useradd --system --no-create-home \
  --home-dir /var/lib/rn-foundation --shell /usr/sbin/nologin rnfoundation
sudo mkdir -p /opt/rn-foundation/admin /var/lib/rn-foundation
sudo chown -R rnfoundation:rnfoundation /var/lib/rn-foundation
sudo chmod 0750 /var/lib/rn-foundation

echo "== 配置 =="
if [ -f /etc/rn-foundation.env ]; then
  echo "   /etc/rn-foundation.env 已存在，保持不变"
else
  sudo install -m 0600 -o root -g root rn-foundation.env.example /etc/rn-foundation.env
  echo "   已从模板创建，去填 CHANGE_ME_* 再启动"
fi

echo "== systemd =="
sudo install -m 0644 rn-foundation-server.service  /etc/systemd/system/
sudo install -m 0644 rn-foundation-indexer.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "== nginx =="
# 后缀必须是 .conf：nginx.conf 里 include 的是 conf.d/*.conf
sudo install -m 0644 nginx-rn-foundation.conf /etc/nginx/conf.d/rn-foundation.conf
sudo nginx -t
sudo systemctl reload nginx

cat <<'NEXT'

装好了。接下来按顺序：

  1. 填 /etc/rn-foundation.env 里的 CHANGE_ME_*（数据库四项与 STORAGE_MASTER_KEY
     照抄 web4，ADMIN_API_KEY 自己另生成一把）
  2. 从开发机跑 deploy.sh，把二进制和两份控制台产物送上来
  3. sudo systemctl enable --now rn-foundation-server rn-foundation-indexer
  4. ./setup-tls.sh 申请证书并打开自动续期
NEXT
