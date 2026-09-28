# 防火墙监控运维控制台：当前项目交接

更新：2026-09-28。本文取代迁移初期的目录副本说明；旧阶段过程仍可从 Git 历史与 [五阶段记录](architecture-stage-1-2-summary.md) 追溯。

## 项目身份与发布基线

- 仓库：[puww1010/panos-opretation-agent](https://github.com/puww1010/panos-opretation-agent)。
- PR #2 已将功能分支合并到 `main`，合并提交 `bfd4b2b`，功能基线 `bcb070a`。
- 当前工作分支为 `codex/panos-monitor-native`；克隆部署优先使用已更新的 `main`。
- 主运行入口 `webui/server.js` / `webui/start.sh`；不再维护另一套 `standalone/` 作为运行来源。
- 目前是内部试用源码版本，不是已经验收的跨平台安装产品。

## 必须先读

1. [当前架构与重构原因](ARCHITECTURE.md)：模块边界、执行链、状态归属和剩余限制。
2. [安装与运行](DEPLOY.md)：两组依赖、首次密码、数据路径与真实网络边界。
3. [深度巡检说明](深度健康巡检使用说明.md)：33 项检查、证据覆盖、历史兼容和统一报告。
4. [打包现状](PACKAGING-DEPLOY.md)：旧脚本不可直接作为最新版发行方案。

## 已进入 Git 的功能

五阶段拆分已完成：PAN-OS Adapter、Task Service 与持久化、LLM Service、Auth/Dashboard 与 Router、`app.js` 装配及薄 `server.js`。

后续已提交原生深度巡检、巡检中心合并、统一持久化报告与 JSON/HTML 导出、飞书 CLI 后台路径修复、侧栏一键执行及重复提交保护。运营导航、拓扑和流量窗口/统计也不再属于“迁移副本未提交功能”。

## 当前不要混入的本机改动

截至本次文档更新前，工作区仍有独立的登录页、10 分钟空闲超时及其测试/资源，另有根 `package.json`、旧 `standalone/package.json` 启动脚本调整和运行时任务/模型选择。它们不属于本次文档提交；具体以实时 `git status` 为准，不要按旧清单盲目暂存。

Git 基线的 Auth Service 仍为 `idleMinutes: 0`；本机 10 分钟超时不能当作远端已交付。当前包元数据仍为 WebUI 4.1.0 / MCP 1.3.29，历史安全文档存在不同版本描述，因此以提交 SHA 而不是旧版本号判断功能基线。

## 维护约束

- Router 只维护 HTTP 契约；Task Service 是任务/审计状态唯一业务入口。
- Monitor Service 管规则、证据和覆盖率；Adapter 管固定设备来源和传输。
- 新巡检统一为 `monitor`，旧 `inspect` 历史保持原结构，不重算。
- 任务默认最多 200 条；执行中重启会标记中断，不自动恢复设备事务。
- 报告在 `task.result.monitor`；流量原始明细在内存，重启后需重新查。
- 不自动运行旧 supervisor / 飞书桥接。它们仍有历史路径、固定参数和生命周期风险。
- 禁止输出/提交真实凭据、会话、报告或完整运行时 JSON。运行时文件即使已被忽略，也要核对是否仍被 Git 跟踪。
- 更新代码前确认无执行任务，备份实际数据路径；只读验证优先，设备变更与群消息发送单独授权。

## 验证

从隔离的已提交源码验证，不依赖本机未提交改动：

```bash
node --test webui/test/*.test.js
```

功能基线 `bcb070a` 曾完成 275 项自动回归；这是历史记录，不代替每次修改后的新测试。登录、MCP 握手、真实 PAN-OS 只读数据和飞书双向消息是不同验收项，必须分别说明结果。
