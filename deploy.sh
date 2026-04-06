#!/bin/bash
set -e

echo "==> 构建并部署 CLIProxyAPI..."
docker compose up -d --build

echo "==> 同步管理面板静态文件到 Nginx..."
docker cp cli-proxy-api:/CLIProxyAPI/static/management.html /var/www/cliproxy/management.html
gzip -k -9 -f /var/www/cliproxy/management.html
brotli -9 -k -f /var/www/cliproxy/management.html 2>/dev/null || true

echo "==> 完成！"
docker logs cli-proxy-api --tail 3
