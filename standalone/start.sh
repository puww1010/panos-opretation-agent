#!/bin/bash
# PAN-OS Agent 控制台 - 零 WorkBuddy 依赖启动脚本
# 用法: ./start.sh          （纯 direct 模式，无需任何 WorkBuddy 组件）
#       MCP_ENABLED=1 ./start.sh   （可选：启用本地 MCP server 增强层，需 node 22+ 与 MCP 源码）
set -e
cd "$(dirname "$0")"

# ── 1. 自动检测 Node（优先 $NODE，其次常见路径，最后 PATH）──
if [ -z "$NODE" ]; then
  for c in /opt/homebrew/bin/node /usr/local/bin/node "$HOME/.nvm/versions/node"/*/bin/node; do
    [ -x "$c" ] && NODE="$c" && break
  done
  [ -z "$NODE" ] && NODE="$(command -v node || true)"
fi
if [ -z "$NODE" ] || ! "$NODE" -v >/dev/null 2>&1; then
  echo "❌ 未找到 Node.js。请安装 Node 18+ 或设置 NODE=/path/to/node" >&2
  exit 1
fi
echo "[agent] Node: $($NODE -v) @ $NODE"

# ── 2. LLM 配置（配置对应 *_API_KEY 即启用；未配置则关键词模式）──
# ⚠️ 安全：不再内置任何真实 API Key。客户首次使用请 export DEEPSEEK_API_KEY / QWEN_API_KEY / KIMI_API_KEY，
#    或在 llm-config.json 的 providers.<name>.key 填写（控制台"模型配置"弹窗也可运行时配置）。
export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}"
export QWEN_API_KEY="${QWEN_API_KEY:-}"
export KIMI_API_KEY="${KIMI_API_KEY:-}"
export LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"

# ── 3. 防火墙配置（必填）──
export PANOS_FIREWALLS_CONFIG="${PANOS_FIREWALLS_CONFIG:-$(pwd)/firewalls.json}"

# ── 4. 飞书（可选）：配一个即启用 ──
# export FEISHU_WEBHOOK_URL="https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxx"  # 群机器人（只能发）
# export FEISHU_APP_ID="cli_xxx"; export FEISHU_APP_SECRET="xxx"; export FEISHU_CHAT_ID="oc_xxx"  # 自建应用（可收发）
# export FEISHU_CHAT_ID="oc_0238b0ea1d6d7a74180cfce85b18cf67"

# ── 5. MCP 增强层（可选，默认关闭）──
# export MCP_ENABLED=1
# export MCP_SRC="/path/to/panos-mcp-local/src/index.ts"
# export MCP_CWD="/path/to/panos-mcp-local"
# export MCP_NODE_PATH="${MCP_CWD}/node_modules"

export PORT="${PORT:-8080}"
echo "[agent] LLM: ${LLM_PROVIDER:-keyword} | 防火墙: ${PANOS_FIREWALLS_CONFIG} | MCP: ${MCP_ENABLED:-0}"
exec "$NODE" server.js
