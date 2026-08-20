#!/bin/bash
# PAN-OS Agent 控制台启动脚本（独立部署版 v5）
# 无 WorkBuddy 依赖：MCP server 在 ../mcp/panos-mcp，防火墙配置在 ../cfgs/firewalls.json，
# LLM keys 在 ./llm-config.json（无需环境变量）。
# 可选环境变量：PORT / NODE_BIN / PANOS_MCP_DIR / PANOS_FIREWALLS_CONFIG / LARK_CLI
set -e
cd "$(dirname "$0")"

ROOT="$(cd .. && pwd)"
export NODE_PATH="$(pwd)/node_modules"          # MCP SDK（控制台依赖）
export PANOS_MCP_DIR="${PANOS_MCP_DIR:-$ROOT/mcp/panos-mcp}"
export PANOS_FIREWALLS_CONFIG="${PANOS_FIREWALLS_CONFIG:-$ROOT/cfgs/firewalls.json}"
export PORT="${PORT:-8080}"

echo "[agent] LLM 由 llm-config.json 决定（默认 deepseek）"
echo "[agent] PANOS_FIREWALLS_CONFIG=$PANOS_FIREWALLS_CONFIG"
exec ${NODE_BIN:-node} server.js
