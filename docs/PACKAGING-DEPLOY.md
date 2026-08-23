# PAN-OS Agent 打包部署指南

> 面向交付工程师：把 PAN-OS 防火墙 Agent 控制台打成独立安装包分发给客户。
> 覆盖：依赖盘点 / macOS .app 打包 / Windows exe / Linux systemd / 安全脱敏 / 客户初始化。

---

## 1. 依赖盘点（零 WorkBuddy 依赖）

控制台本体为纯 Node.js 实现，**不依赖 WorkBuddy 运行时**，可完全脱离独立部署。

| 组件 | 依赖项 | 说明 |
|---|---|---|
| `webui/server.js` | Node 22+ · `@modelcontextprotocol/sdk` | 唯一第三方 npm 依赖（webui/node_modules ≈ 21MB） |
| `mcp/panos-mcp` | Node 22+（`--experimental-strip-types`）· TypeScript 源码 | MCP 增强层（node_modules ≈ 65MB）；不启用则走纯 direct 模式 |
| 飞书桥接 | `lark-cli`（可选）或 Python 3 | `standalone/feishu-bridge.py` 为纯飞书 API 实现（零依赖） |
| 常驻保活 | Python 3 | `panagent-supervisor.py`（可选，无则手动启动） |

> ✅ 结论：客户环境只需 **Node 22+（或随包内嵌）**；飞书/Python 均为可选能力。

### 1.1 MCP 通道架构（脱离 WorkBuddy 如何工作）

控制台自包含一套完整的 MCP 实现（**MCP Client + 内置 MCP Server**），与 WorkBuddy 的 MCP 连接器完全无关，独立部署后照常工作：

```
浏览器 WebUI
   │  HTTP / JS
   ▼
Node 后端 webui/server.js ──────────────┬───────────────────────────────┐
   │  MCP Client（官方 @modelcontextprotocol/sdk）   │  直连层 direct*() 函数          │
   │  stdio 进程通信                    │  HTTPS（Node https 模块）       │
   ▼                                    ▼                               ▼
mcp/panos-mcp 子进程（项目自带）    ──HTTPS──▶   PAN-OS 防火墙 XML API
```

- **MCP Client**：`webui/server.js` 用官方 npm 包 `@modelcontextprotocol/sdk`，`connect()` 通过 `StdioClientTransport` 拉起项目自带的 `mcp/panos-mcp/src/index.ts` 子进程（`NODE --experimental-strip-types`）。两边用 **stdio 管道**通信——纯本地进程间通信，不注册任何外部平台。
- **MCP Server**：`mcp/panos-mcp` 是项目源码，读 `cfgs/firewalls.json` 的 API Key，调用 PAN-OS XML API。
- **直连层**：`directOp()` / `directConfigSet()` / `directConfigDelete()` / `directConfigMove()` / `directLog()` 等函数用 Node `https` 模块**直接**调 PAN-OS，不经过 MCP。原因：MCP 部分工具（如 `move_security_rule`）v3Schema 校验存在故障，故封禁/删除/移动/禁用等变更操作默认走直连，MCP 仅作查询兜底。
- **路由规则**：`webui/tools-config.json` 可对每个工具指定 `mcp` / `direct` / `auto`（默认 auto：direct 优先，失败回退 MCP）。
- **结论**：脱离 WorkBuddy 后唯一外部对象是被管理的 **PAN-OS 防火墙本身**；MCP 只是"本地两个进程之间的消息协议"，不是外部依赖。

---

## 2. 安全脱敏（打包强制步骤）

**开发机上的真实凭据不得进入安装包**，打包脚本已内置脱敏：

| 敏感文件 | 打包前 | 打包后（安装包内） |
|---|---|---|
| `webui/llm-config.json` | 真实 LLM API Key ×3 | providers 结构保留，**key 清空** |
| `cfgs/firewalls.json` | 真实 PA 设备 IP + api_key | 设备占位，**api_key 清空** |
| `standalone/start.sh` | （已移除硬编码 key） | 仅保留 export 占位 |

脱敏由 `scripts/build-app.sh` 的 **2b 步骤**自动完成（Python 内联脚本），无需人工干预。

---

## 3. 打包方案

### 3.1 macOS（已实现，`scripts/build-app.sh`）

产物：`dist/PAN-OS Agent.app`（≈197MB，内嵌 Node 运行时，双击即用）。

```bash
# 指定 Node 二进制来源后一键打包
NODE_SRC="$(command -v node)" bash scripts/build-app.sh
# 产物验证（必须）
grep -r "sk-" "dist/PAN-OS Agent.app" --include="*.json" | wc -l   # 期望 0
```

安装包结构：

```
PAN-OS Agent.app/
├── Contents/
│   ├── Info.plist                 # Bundle 元信息（v4.1.0）
│   ├── MacOS/launcher             # 启动器：拉起 supervisor + 自动开浏览器
│   └── Resources/
│       ├── node-dir/node          # 内嵌 Node 运行时（110MB）
│       └── console/               # 控制台全量（已脱敏）
│           ├── webui/             # 前端 + server.js + llm-config.json（key 空）
│           ├── mcp/panos-mcp/     # MCP 层（含 node_modules）
│           ├── cfgs/firewalls.json（api_key 空）
│           ├── panagent-supervisor.py
│           └── feishu-bridge.py
```

客户使用：拖到 `/Applications` → 双击启动 → 自动打开 `http://localhost:8080`。
已运行实例再双击仅打开浏览器（launcher 检测 8080 端口）。

### 3.2 Windows（建议，未实现）

推荐 **pkg**（Node 官方）打包成单 exe：

```bash
# 在 webui/ 下
npx pkg server.js --targets node22-win-x64 --output "PAN-OS-Agent.exe"
```

要点：
- 需把 `index.html`、`llm-config.json` 作为 `assets` 打进 pkg（pkg 不自动含静态文件）
- MCP 增强层若启用，同样打 `mcp/panos-mcp`（或直接随目录分发 + `PANOS_MCP_DIR` 环境变量）
- 建议配合 `node-windows` 或 NSSM 注册 Windows 服务实现开机自启
- 防火墙放行 8080 端口

### 3.3 Linux（建议，未实现）

产物：`tar.gz` + systemd 服务。

```bash
# 打包
tar -czf panos-agent-linux.tar.gz \
  webui/ mcp/ cfgs/ panagent-supervisor.py feishu-bridge.py scripts/ \
  --exclude='*/node_modules/.cache'
```

systemd 单元 `/etc/systemd/system/panos-agent.service`：

```ini
[Unit]
Description=PAN-OS Agent Console
After=network.target

[Service]
Type=simple
User=panos
WorkingDirectory=/opt/panos-agent
Environment=NODE_BIN=/usr/bin/node
ExecStart=/usr/bin/python3 /opt/panos-agent/panagent-supervisor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now panos-agent
# 查看状态/日志
systemctl status panos-agent
journalctl -u panos-agent -f
```

> Linux 版注意：Node 官方二进制适用于 glibc；若客户是 Alpine/musl，需换对应构建。

---

## 4. 客户首次初始化（配置向导方案）

### 4.0 WebUI 登录认证（发布公网 / 客户交付必读）

- 首次启动自动生成 `cfgs/auth.json`：账号 `admin` + **随机密码**（打印在控制台日志，如 `[auth] ⚠️ 首次启动：WebUI 登录账号 = admin / 密码 = xxxxxxxx`）。
- **所有 `/api/*` 接口需 `Authorization: Bearer <token>`**（用户登录会话或 `internal_token`）；未认证返回 401，前端显示登录覆盖层。
- 登录：`POST /api/auth/login`（会话 7 天）；修改密码：右上角「🔑 改密」（校验旧密码 + 新密码 ≥8 位，成功后清空全部会话强制重登）。
- 飞书 bridge 通过 `cfgs/auth.json` 的 `internal_token` 自动调用 API（或环境变量 `PANOS_WEB_INTERNAL_TOKEN`），无需人工登录。
- 忘记密码：删除 `cfgs/auth.json` 重启，即重新生成随机密码。
- **发布公网三阶段**：① 本认证 → ② 网络方案（云服务器 Nginx 反代 / 内网穿透 / 家庭公网 IP）→ ③ HTTPS 证书 + 安全组规则。无回环豁免（Nginx 反代也必须认证）。

### 4.1 现状：手动填两个文件

1. **防火墙连接**：编辑 `cfgs/firewalls.json`

```json
{
  "firewalls": [{
    "name": "pa-440",
    "host": "192.168.0.250",
    "api_key": "填入PA设备的API Key"
  }]
}
```

2. **LLM API Key**：控制台右上角「⚙️ 模型配置」弹窗填入（运行时生效，无需重启）

### 4.2 建议：首次启动配置向导（未实现，推荐开发）

- 检测 `firewalls.json` 的 `api_key` 为空 或 `llm-config.json` 的 providers key 全空 → 打开引导弹窗
- 表单字段：设备名 / IP / API Key / 默认 LLM / 各 LLM API Key
- 保存即写 `cfgs/firewalls.json` + `webui/llm-config.json`，随后自动刷新页面
- 复用现有 `模型配置` 弹窗的保存逻辑，新增防火墙配置区块即可

---

## 5. 客户初始化指引（随包分发）

打包时自动生成 `客户初始化指引.md` 放入安装包 Resources（建议，未实现）。内容模板：

```markdown
# 初始化指引（首次使用 5 分钟）

## 1. 启动
- macOS：双击 PAN-OS Agent.app（或将 app 拖入 /Applications 后启动）
- 浏览器自动打开 http://localhost:8080，或手动访问

## 2. 配置防火墙连接
编辑安装包内 console/cfgs/firewalls.json：
  name    = 设备名（随意）
  host    = PA 防火墙管理 IP
  api_key = PA 管理 API Key（PAN-OS: Device > Setup > Operations > Generate API Key）

## 3. 配置 AI 模型（可选）
控制台右上角「⚙️ 模型配置」→ 填写 DeepSeek/通义千问/Kimi 的 API Key → 保存

## 4. 飞书通知（可选）
设置 FEISHU_WEBHOOK_URL 或 app_id/app_secret/chat_id 后重启

## 5. 开始使用
在命令中心输入自然语言即可：设备状态 / 完整巡检 / 流量日志 / 封禁 1.2.3.4 ...
```

---

## 6. 交付前自检清单

| 检查项 | 命令 / 方法 | 通过标准 |
|---|---|---|
| 敏感信息脱敏 | `grep -r "sk-" <安装包> --include="*.json"` | 输出 0 |
| 认证生效 | 未带 token 访问 `/api/overview` | HTTP 401 |
| 登录可用 | `POST /api/auth/login`（admin + 日志随机密码） | 返回 `{ok:true,token}` |
| 语法完整性 | 内嵌 node `--check webui/server.js` | 无报错 |
| 依赖完整性 | 检查包内 `webui/node_modules`、`mcp/panos-mcp/node_modules` | 存在 |
| 干净环境启动 | 在无 Node 的虚拟机双击 .app | 8080 可访问 |
| 防火墙连通 | 首页 KPI 显示设备型号/会话数 | PA-440 等数据出现 |
| LLM 生效 | 提交一个查询任务，卡片显示 `🟦 DeepSeek` 等标签 | 有结果 |
| 任务持久化 | 提交任务 → 重启 → 任务列表仍在 | tasks.json 恢复 |

---

## 7. 版本发布流程

```bash
# 1. 修改版本号
sed -i '' 's/4\.1\.0/4.2.0/' webui/package.json scripts/build-app.sh

# 2. 重新打包
NODE_SRC="$(command -v node)" bash scripts/build-app.sh

# 3. 自检（见第 6 节）

# 4. 归档
cd dist && zip -r "PANOS-Agent-4.2.0-macOS.zip" "PAN-OS Agent.app"
```

---

## 附：目录职责速查

| 目录 | 职责 | 是否进安装包 |
|---|---|---|
| `webui/` | 控制台前端 + 后端 server.js | ✅（脱敏后） |
| `mcp/panos-mcp/` | MCP 增强层 | ✅（含 node_modules） |
| `cfgs/` | 防火墙连接配置 | ✅（脱敏后） |
| `cfgs/auth.json` | WebUI 登录凭据（密码 sha256 + 会话 + internal_token） | ⚠️ **不随包**（客户首启自动生成） |
| `reports/` | 合规巡检报告产物 | ⚠️ 客户运行期生成，不随包 |
| `docs/` | 本文档及规格 | 可选 |
| `.state/` | 飞书游标状态 | 打包时保留占位即可 |
