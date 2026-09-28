# 源码安装、配置与运行

更新：2026-09-28。适用于已合入 PR #2 的 `main`，功能基线 `bcb070a`、合并提交 `bfd4b2b`；不是旧 `standalone/`，也不是尚未完成的桌面安装包。

## 1. 运行位置

控制台应部署在能访问防火墙管理 API 的电脑或内网主机。浏览器访问控制台，Node 后端及本地 MCP 子进程访问 PAN-OS；模型辅助功能需访问所选 LLM 提供方，飞书功能需访问飞书。

当前主要验证环境为 macOS Intel + Node 22.19.0。Linux 可按源码方式适配，但不能把本机验证当作 Linux 托管或 Windows 安装验收。自启动、HTTPS、桌面安装包和跨 CPU 兼容需分别验证。

## 2. 依赖与安装

| 位置 | 依赖声明 | 用途 |
| --- | --- | --- |
| 系统 | Node.js ≥22.19.0、npm、Git、Bash | HTTP 服务、MCP TypeScript 源码运行、安装与启动 |
| `webui/package.json` | `@modelcontextprotocol/sdk` ^1.30.0 | MCP Client / stdio 传输 |
| `mcp/panos-mcp/package.json` | `@modelcontextprotocol/sdk` ^1.30.0、`zod` ^4.0 | MCP Server 与参数校验 |
| 同上 | `fast-xml-parser` ^5.10.1、`undici` ^8.10.0、`socks` ^2.8.3 | XML、HTTP 与代理 |
| 同上 | `@napi-rs/keyring` ^1.2.0 | 系统密钥链；包含平台相关依赖，须在目标系统安装 |
| 可选 | `lark-cli` | 主控制台飞书消息和报告摘要发送 |
| 可选 | Python 3 | 旧飞书消息桥接与守护脚本；不是 WebUI/深度巡检必需依赖 |

以上是源码声明范围，不是锁定版本。MCP 开发工具另有 TypeScript、esbuild、Vitest 和 Node 类型声明，不属于源码运行必需的开发环境。

```bash
git clone --branch main --single-branch \
  https://github.com/puww1010/panos-opretation-agent.git
cd panos-opretation-agent
node --version
npm --version
npm install --prefix webui --omit=dev --ignore-scripts
npm install --prefix mcp/panos-mcp --omit=dev --ignore-scripts
```

Adapter 直接启动 `node --experimental-strip-types mcp/panos-mcp/src/index.ts`，不要求生成 `dist/`。MCP 的 `prepare` 会触发 TypeScript 编译，上述命令显式跳过安装脚本；开发或编译 MCP 时须另装开发依赖并验证构建，不能把跳过脚本当作构建成功。

仓库忽略了 `package-lock.json`，全新克隆没有可用于 `npm ci` 的锁文件。正式可重复发行还需锁定依赖。命令行为参考 [npm install](https://docs.npmjs.com/cli/v11/commands/npm-install)、[npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci) 和 [生命周期脚本](https://docs.npmjs.com/cli/v11/using-npm/scripts)。

## 3. 首次配置与启动

以下用于**全新源码安装**。已有服务升级不能用模板覆盖配置。

### 3.1 创建自己的配置

在项目根目录执行：

```bash
umask 077
mkdir -p .state
test -e cfgs/firewalls.json || cp cfgs/firewalls.example.json cfgs/firewalls.json
test -e webui/llm-config.json || cp webui/llm-config.example.json webui/llm-config.json
chmod 600 cfgs/firewalls.json webui/llm-config.json
```

用本地编辑器修改 `cfgs/firewalls.json` 的设备名称、管理地址与 API Key。下面仅说明格式，`192.0.2.10` 是文档地址，不能用于真实连接：

```json
{
  "firewalls": [
    { "name": "YOUR_FIREWALL_NAME", "host": "192.0.2.10", "api_key": "YOUR_API_KEY_HERE" }
  ]
}
```

LLM 可先不配置；需要时在登录后的模型配置界面填写提供方、实际可用模型和密钥。模板中的模型名称不保证对你的账号可用。不要把密钥写入 `start.sh`、命令参数、提交或截图。

### 3.2 隐藏输入初始化密码并启动

当前没有首次启动图形化密码向导。首次创建 `cfgs/auth.json` 时，Auth Service 从 `PANOS_WEB_PASSWORD` 初始化管理员密码；不设置则随机生成且不输出，不能再按旧文档“到日志里找密码”。

下面在 Bash 中隐藏输入，不将实际密码放进命令历史；示例额外要求至少 12 位。仅用于尚无 `cfgs/auth.json` 的新安装：

```bash
bash -c '
  read -r -s -p "设置首次登录密码（至少 12 位）: " PANOS_WEB_PASSWORD
  printf "\n"
  if [ "${#PANOS_WEB_PASSWORD}" -lt 12 ]; then
    printf "密码长度不足，未启动。\n"
    exit 1
  fi
  export PANOS_WEB_PASSWORD
  export TASKS_FILE="$PWD/.state/tasks.json"
  export AUDIT_FILE="$PWD/.state/audit-events.json"
  export LLM_CHOICE_FILE="$PWD/.state/llm-choice.json"
  umask 077
  exec bash webui/start.sh
'
```

浏览器访问 `http://localhost:8080`，账号 `admin`，使用刚输入的密码。`.state/` 保存这份新部署自己的任务、审计和模型选择，避免继承仓库历史跟踪的任务记录；这只是现有路径覆盖能力，不是新实现的统一用户数据目录。

**已有 `auth.json` 时环境变量不会重置密码**。使用原密码和界面改密流程，不要删除认证文件来“修复登录”。认证文件仍固定在 `cfgs/auth.json`。

后续启动沿用相同数据路径，无需再次设置初始化密码：

```bash
umask 077
export TASKS_FILE="$PWD/.state/tasks.json"
export AUDIT_FILE="$PWD/.state/audit-events.json"
export LLM_CHOICE_FILE="$PWD/.state/llm-choice.json"
bash webui/start.sh
```

前台运行可用当前终端 `Ctrl+C` 停止；先确认没有执行中的任务。不要同时启动两份服务写同一组 JSON 文件。

## 4. 配置与数据路径

默认路径相对于项目位置；自行传入环境变量时建议使用绝对路径。

| 项目 | 默认位置 / 变量 | 说明 |
| --- | --- | --- |
| HTTP 端口 | `PORT=8080` | 未显式绑定回环，不等于只允许本机访问 |
| Node / MCP | `NODE_BIN`、`PANOS_MCP_DIR` | 启动子进程与源码目录 |
| 防火墙连接 | `cfgs/firewalls.json` / `PANOS_FIREWALLS_CONFIG` | 可含敏感 API Key |
| 认证 | `cfgs/auth.json` | 没有 `AUTH_FILE` 环境变量覆盖；含密码哈希、会话和内部令牌 |
| 任务 / 审计 | `cfgs/tasks.json` / `TASKS_FILE`；`cfgs/audit-events.json` / `AUDIT_FILE` | 本文新安装改放 `.state/`，父目录须先存在 |
| 模型配置 / 选择 | `webui/llm-config.json` / `LLM_CONFIG`；`cfgs/llm-choice.json` / `LLM_CHOICE_FILE` | 配置可含密钥，选择为运行时状态 |
| 工具路由 | `webui/tools-config.json` / `TOOLS_CONFIG` | `mcp`、`direct`、`auto`；新安装不必先改路由 |
| 拓扑命名 | `cfgs/topology.json` | 可选；当前路径固定 |
| 飞书发送 | `LARK_CLI`、`FEISHU_CHAT_ID` | 主服务 CLI 与群配置；不自动完成飞书授权 |

## 5. 只读验证与测试

未登录时检查页面和认证边界，不创建任务：

```bash
curl --silent --output /dev/null --write-out '%{http_code}\n' http://localhost:8080/
curl --silent --output /dev/null --write-out '%{http_code}\n' http://localhost:8080/api/tasks
```

预期分别 `200`、`401`。随后浏览器登录，查看概览、任务列表和巡检目录。MCP 握手仅证明子进程能通信，不证明防火墙认证成功。

在项目根目录运行回归：

```bash
node --test webui/test/*.test.js
```

自动测试不代表真实设备支持所有指令；不在安装验证中创建候选配置、审批、commit 或发送飞书消息。

## 6. 飞书是可选集成

主控制台使用 `lark-cli` 发送消息。目标机器需自行安装、登录正确应用身份并明确配置目标群，机器人必须在群内且拥有权限。`LARK_CLI` 可指定路径；代码会查 PATH 并兼容旧机器的 WorkBuddy 安装位置，但该路径不是发行依赖。

不要沿用代码内的开发群默认值。主服务的 `FEISHU_CHAT_ID` 不会自动改写旧 `feishu-bridge.py`：后者仍有固定群、固定 `localhost:8080` 和独立 `.state` 游标。双向桥接须单独核对这些设置、权限和回执，不能以“daemon 运行中”证明链路健康；也不能把 `standalone/` 的飞书配置方式套到主程序。

- `spawn lark-cli ENOENT`：核对可执行路径与后台进程的 Node 路径。
- `230002`：核对当前机器人身份是否加入目标群。
- `230027`：继续核对权限和租户策略；发送成功不证明读取/自动回执也成功。
- `/api/feishu/push-report` 返回 400：先核对是否已有结束的新版巡检报告及请求格式；旧 `inspect` 历史不是新版推送来源。

## 7. 升级、备份与限制

- 升级前检查分支/未提交改动并记录旧提交；无执行任务后，将实际配置、任务、审计、认证备份到受保护的本地目录，不上传 GitHub。
- 先确认数据路径再切换代码；本手册不提供覆盖运行目录、强制重置或一键删除数据的命令。
- 历史任务默认上限 200，不是无限归档；重启中断的任务不自动重放。清理任务可能同时清掉随任务保存的巡检报告，重要报告应先导出。
- 流量全量明细仅在内存，摘要和 50 条预览可恢复；重启后原始明细需重新查询。
- 本分支 `idleMinutes: 0`；维护者本机的 10 分钟超时与新登录页尚未独立提交，本次不混入代码改动。
- 原生 HTTP 无内建 HTTPS；部分 PAN-OS 直连禁用证书校验，缺少多用户 RBAC/SSO，应限定可信网络并另做生产安全评审。
- Linux 托管、Windows 安装、macOS 签名/公证和自动升级尚未完成当前版本验收；旧打包/守护脚本不能直接当成发行方案。

排障顺序：浏览器到 HTTP → 登录认证 → MCP 子进程 → 防火墙 API → 指令支持情况。只分享脱敏错误、版本与路径结构，不分享完整配置或令牌。
