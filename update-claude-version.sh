#!/bin/bash
# 自动检测 Claude Code 最新版本并更新配置
set -e

CONFIG="/root/CLIProxyAPI-main/config.yaml"
LOG="/root/CLIProxyAPI-main/logs/version-update.log"
mkdir -p "$(dirname "$LOG")"

# 获取最新版本
LATEST=$(npm view @anthropic-ai/claude-code version 2>/dev/null)
if [ -z "$LATEST" ]; then
  echo "$(date) [ERROR] 无法获取最新版本" >> "$LOG"
  exit 1
fi

# 获取当前配置的版本
CURRENT=$(grep 'user-agent:' "$CONFIG" | grep -oP 'claude-cli/\K[0-9.]+' | head -1)
if [ -z "$CURRENT" ]; then
  CURRENT="unknown"
fi

# 对比
if [ "$CURRENT" = "$LATEST" ]; then
  echo "$(date) [OK] 版本一致: $CURRENT" >> "$LOG"
  exit 0
fi

echo "$(date) [UPDATE] $CURRENT → $LATEST" >> "$LOG"

# 更新 config.yaml 中的版本号
sed -i "s|claude-cli/$CURRENT|claude-cli/$LATEST|g" "$CONFIG"

# 重启服务使配置生效
cd /root/CLIProxyAPI-main && docker compose restart >> "$LOG" 2>&1

echo "$(date) [DONE] 已更新并重启" >> "$LOG"
