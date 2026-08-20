# PAN-OS 防火墙 Agent — 零 WorkBuddy 依赖部署包

纯 Node.js 单服务 + 可选 Python 飞书桥接。**不依赖 WorkBuddy / MCP connector / lark-cli**。

## 架构

```
浏览器 → localhost:8080 (webui) ─┐
飞书群 → feishu-bridge.py (轮询) ─┼→ server.js → PAN-OS HTTPS API / LLM API
                                  └  (可选 MCP 增强层，默认关闭)
```

## 依赖

| 组件 | 要求 |
|---|---|
| Node.js | ≥ 18（LLM/HTTP 均内置模块，无第三方依赖） |
| Python | ≥ 3.8（仅飞书桥接需要，可选） |
| 防火墙 | PAN-OS API key（firewalls.json） |
| LLM | DeepSeek API key（可选，无 key 走关键词模式） |

## 快速开始

```bash
# 1. 配置
cp firewalls.example.json firewalls.json
vim firewalls.json        # 填 host + api_key

# 2. 启动（自动检测系统 node，纯 direct 模式）
./start.sh
# → http://localhost:8080

# 3. 可选：启用 MCP 增强层（需要 node 22+ 与 panos-mcp-local 源码）
npm install   # 安装 @modelcontextprotocol/sdk（optional）
export MCP_ENABLED=1 MCP_SRC=/path/src/index.ts MCP_CWD=/path
./start.sh
```

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `PANOS_FIREWALLS_CONFIG` | 是* | firewalls.json 路径（默认 ./firewalls.json） |
| `DEEPSEEK_API_KEY` | 否 | LLM 规划（未配置走关键词模式） |
| `LLM_PROVIDER` | 否 | deepseek / qwen / kimi，默认 deepseek |
| `PORT` | 否 | 监听端口，默认 8080 |
| `NODE` | 否 | 指定 node 路径（默认自动检测） |
| `MCP_ENABLED` / `MCP_SRC` / `MCP_CWD` / `MCP_NODE_PATH` | 否 | MCP 增强层（默认关） |
| `FEISHU_WEBHOOK_URL` | 否 | 群机器人 webhook（只能发，控制台"飞书集成"卡用） |
| `FEISHU_APP_ID` / `FEISHU_APP_SECRET` / `FEISHU_CHAT_ID` | 否 | 自建应用（bridge 收发用，见下） |

*server.js 默认兜底读 `~/.config/panos-mcp/firewalls.json`，建议显式配置。

## 飞书控制（feishu-bridge.py）

需要**飞书自建应用**（机器人）：
1. open.feishu.cn 创建应用 → 启用机器人
2. 权限：`im:message`（发）、`im:message:readonly`（收）、`im:chat`（读群）
3. 把机器人拉进目标群，获取 chat_id（群 URL 或 API）
4. 添加应用到群并发布版本

```bash
export FEISHU_APP_ID="cli_xxx"
export FEISHU_APP_SECRET="xxx"
export FEISHU_CHAT_ID="oc_xxx"
python3 feishu-bridge.py --daemon   # 轮询群消息 → 调控制台 /api/task → 回复结果
```

飞书支持的命令（同控制台）：
- 查询：`查一下防火墙状态` / `许可证` / `流量日志`
- 巡检：`完整巡检`
- 审计：`谁在10分钟前修改了策略？`
- 诊断：`192.168.1.2 不能访问 gmail，帮我查原因`
- 变更（审批闭环）：`创建地址对象 xxx 值 1.2.3.4` → 回复「批准」→ 执行 → 回复「确认」→ commit

## 任务类型

| 类型 | 说明 |
|---|---|
| query | 设备/许可证/会话/对象等查询（15+ 工具直连） |
| inspect | 合规巡检（评级+检查项） |
| diag | 故障诊断（LLM 综合根因/置信度/建议） |
| audit | 配置变更审计（谁/何时/改了什么） |
| change | 变更审批闭环（创建/删除/封禁 + commit） |

## 日志与排错

```bash
tail -f /tmp/webui.log        # 控制台日志
curl http://localhost:8080/api/tasks   # 任务状态
curl http://localhost:8080/api/llm/log # LLM 决策日志
```

## 与 WorkBuddy 版差异

- MCP 117 工具 → **全部改直连**（日志 directLog / 查询 directRunOp / 变更 directConfig，已验证等效）
- lark-cli → **飞书开放平台 API**（自持 App 凭据）
- 硬编码路径 → 环境变量 + 自动检测
