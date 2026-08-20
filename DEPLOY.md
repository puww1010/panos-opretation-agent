# PAN-OS Agent 控制台 — 独立部署说明（脱离 WorkBuddy）

控制台已去除对 WorkBuddy 的一切硬编码路径依赖，可整体拷贝到任意 Linux/macOS 主机独立运行。

## 1. 运行时要求

| 组件 | 版本 | 说明 |
|---|---|---|
| Node.js | ≥ 22 | 需支持 `--experimental-strip-types`（MCP server 直接跑 TS 源码） |
| Python 3 | ≥ 3.9 | 仅飞书桥 + supervisor 需要；控制台本体不需要 |
| lark-cli（可选） | - | 仅飞书桥需要；不配则飞书功能离线，控制台其他功能正常 |

## 2. 项目结构

```
Palo-Alto-Firewall-Agent-Console/
├── webui/
│   ├── server.js          # 控制台（Node 原生 http，无框架）
│   ├── index.html         # 前端单页
│   ├── llm-config.json    # LLM provider + API keys（明文，自包含）
│   ├── package.json       # 依赖：@modelcontextprotocol/sdk
│   ├── node_modules/      # 已安装（拷贝时一起带走）
│   └── start.sh           # 启动脚本
├── mcp/
│   └── panos-mcp/         # PAN-OS MCP server（含 src/ + node_modules/）
├── cfgs/
│   └── firewalls.json     # 防火墙 host + api_key
├── feishu-bridge.py       # 飞书轮询桥（可选）
├── panagent-supervisor.py # 常驻守护（double-fork 保活）
└── reports/               # 报告输出
```

## 3. 部署步骤

```bash
# ① 整体拷贝项目到目标主机
scp -r Palo-Alto-Firewall-Agent-Console user@host:~/

# ② （可选）如 node_modules 未随包走，重新安装：
cd Palo-Alto-Firewall-Agent-Console/webui && npm install
cd ../mcp/panos-mcp && npm install

# ③ 配置防火墙连接：编辑 cfgs/firewalls.json
#    { "firewalls": [ { "name": "pa440", "host": "防火墙IP", "api_key": "你的API key" } ] }
#    （api_key 生成：防火墙 Web 界面 → 设备 → 管理 → 管理访问 → API Key，或 CLI: request keygen）

# ④ 配置 LLM（可选）：编辑 webui/llm-config.json 填 base_url/model/key
#    不配置则所有查询走关键词匹配模式，控制台仍可用

# ⑤ 启动（前台验证）
cd webui && bash start.sh

# ⑥ 常驻运行
python3 ../panagent-supervisor.py --daemon
#    （Linux/systemd 可用 launchd/systemd 托管 supervisor；Windows 可用 NSSM/Task Scheduler）
```

## 4. 环境变量（全部可选）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | 8080 | 监听端口 |
| `NODE_BIN` | `node` | Node 可执行文件路径 |
| `PANOS_MCP_DIR` | `../mcp/panos-mcp` | MCP server 目录 |
| `PANOS_FIREWALLS_CONFIG` | `../cfgs/firewalls.json` | 防火墙配置路径 |
| `LARK_CLI` | `lark-cli` | 飞书 CLI 绝对路径（可选） |
| `FEISHU_CHAT_ID` | 内置 | 飞书群 chat id（可选） |

## 5. 常见问题

- **MCP connected 失败**：检查 `mcp/panos-mcp/node_modules` 是否完整（`npm install` 重装），及 `cfgs/firewalls.json` 的 key 是否有效。
- **只读查询能用但变更失败**：直连通道（direct API）通常正常；变更/commit 需确认 key 有配置权限。
- **飞书离线**：未配置 `LARK_CLI` 或未安装 lark-cli，属预期（可选功能）；控制台不受影响。
- **LLM 未参与**：默认 deepseek；UI 可切 qwen（临时，刷新回默认）。仅"非精确匹配"输入触发 LLM 规划。
- **变更两步审批**：`approve`（写候选）→ `confirm`（真 commit）。candidate 用 type=config、commit 用 POST+async，能正确拿到 job 并轮询。

## 6. 安全提示

- `cfgs/firewalls.json` 与 `webui/llm-config.json` 含明文 API key，请限制文件权限（`chmod 600`）并妥善保管。
- 控制台无登录鉴权，仅建议在可信内网运行，或置于反向代理后加 Basic Auth。
