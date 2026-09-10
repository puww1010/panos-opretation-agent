# 防火墙监控运维控制台：项目交接说明

## 项目身份

| 项目 | 防火墙监控运维控制台 |
|---|---|
| 本地目录 | `/Users/vpeng/Documents/ChatGPT/防火墙监控运维控制台` |
| Git 基线 | `aa6a076`（`main`） |
| 运行入口 | `webui/start.sh`，默认 `http://localhost:8080` |
| 运行范围 | 内部测试环境；变更配置仍须经过候选、审批和确认提交流程 |

本项目从原开发目录完整复制了 Git 历史和当时的工作区改动。原目录仍保留，作为迁移前的追溯来源；后续开发应以本目录为准。

## 已完成的架构演进

既定五阶段架构调整已完成，详细前后对比见 [architecture-stage-1-2-summary.md](architecture-stage-1-2-summary.md)：

1. PAN-OS Adapter 统一 MCP、直接 HTTPS/XML、工具路由和凭据读取边界。
2. Task Service 成为任务状态、审计、候选、提交、查询、巡检和诊断的唯一业务入口。
3. LLM Service 管理模型选择、上下文、意图解析、查询摘要和诊断综合。
4. Router Layer 按 Auth、Dashboard、LLM、Task、Operations 与静态资源分组，`server.js` 不再承担业务路由。
5. `app.js` 作为依赖装配根，`server.js` 保持薄入口；已完成只读验证和回归测试。

当前主要边界为：`webui/app.js` 装配依赖，`webui/routes/` 管理 HTTP 契约，`webui/services/` 管理业务状态，`webui/adapters/panos-adapter.js` 处理 PAN-OS/MCP 传输。

## 当前未提交工作

以下改动已随项目副本保留，但尚未创建新的 Git 提交：

- 运营侧栏、后端监控入口和控制台名称调整；
- 流量日志默认使用最近 10 分钟窗口；显式时间窗口和“最新 N 条”输入优先；
- 默认流量窗口读取上限提高到 1000 条；任务记录仅保存 50 条预览；
- 流量结果增加总量、时间范围、按分钟趋势、Top 源/目的/应用/动作统计；
- 当前服务运行期间可按 50 条分页查看已读取日志，并导出 JSON/CSV；若达到 1000 条会提示可能截断；
- 对应 Task Service、Task Router、Task Planner、静态页面和回归测试。

提交前应只暂存源码、测试和文档；不要把运行时数据或凭据混入提交。

## 已知边界与下一步

1. 流量日志当前采用“读取上限提升到 1000”而不是 XML 日志作业分页。原因是尚未确认目标 PAN-OS 版本的分页参数契约；不能猜测性地写入 `skip` 或 `offset`。
2. 达到 1000 条时，导出仅包含本次读取集合。若要保证高流量环境下完整、无遗漏的十分钟日志，需要先对测试防火墙做一次只读分页兼容性验证，再实现逐页拉取。
3. 历史任务在控制台重启后仍可查看其摘要和 50 条预览；完整的当次原始日志只保存在 Task Service 内存中，重启后需要重新运行该查询才能再次分页或导出。
4. 当前项目沿用内部测试策略：`idleMinutes: 0`，即不启用无操作 15 分钟自动退出。正式环境上线前需重新评估会话超时、SSO 与角色权限。

## 安全与运行时文件

以下文件可能包含凭据、会话或运行时数据，均不应提交、展示或复制到外部仓库：

- `cfgs/auth.json`
- `cfgs/firewalls.json`
- `webui/llm-config.json`
- `.env*`、`*.api_key`

新机器或新目录部署时，使用项目内的 `cfgs/firewalls.example.json` 与 `webui/llm-config.example.json` 创建本地配置；将真实值仅保留在本机安全存储或环境变量中。

## 验证基线

迁移前最后一次全量验证：

```bash
node --test webui/test/*.test.js
```

结果为 `71/71` 通过。迁移后的工作区应在安装依赖并完成本地凭据配置后重新执行该命令。

## 建议的新 Codex 任务首条提示

```text
你正在维护“防火墙监控运维控制台”。先阅读 docs/PROJECT_HANDOVER.md 和 docs/architecture-stage-1-2-summary.md，再检查 git status。保持现有分层边界：Router 不直接改任务状态，Task Service 是状态变更唯一入口，PAN-OS Adapter 负责传输。绝不输出、提交或修改真实凭据；任何防火墙写配置操作必须走既有候选、审批和确认提交流程。
```
