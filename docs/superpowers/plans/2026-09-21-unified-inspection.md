# Unified Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 单入口、单执行链、统一新报告、历史兼容。

**Architecture:** 保留 Monitor Service 的纯检查与固定采集；Task Service 作为唯一报告来源；别名入口统一分发 monitor，删除旧执行器但保留历史渲染。

**Tech Stack:** 现有 CommonJS、node:test、原生 HTML/JS；不添加依赖。

## Global Constraints

只读设备访问；不实际发送飞书消息；不打印凭据；不修改用户已有登录页、认证策略和运行配置；未知不能假绿；保留旧历史；所有新巡检状态由 Task Service 管理；不推送 GitHub。工作在用户唯一代码目录和现有功能分支，主代理统一提交自有片段，子代理不操作索引或服务。

### Task 1: 迁入旧巡检独有检查

Files: create `webui/services/monitor/compliance-checks.js`, `webui/test/monitor-compliance.test.js`; modify `webui/services/monitor/{sources,service}.js`, `webui/adapters/panos-adapter.js` and adapter tests. 子代理只拥有这些文件。request.js 由主代理维护。

Interfaces: `complianceChecks` 数组，沿用 `{id,category,label,sources,evaluate}`。新增检查 ID：`policy_hygiene`、`wildfire`、`content_versions`、`logging_health`。新采集 source：`security_rules`、`wildfire`、`content_versions`、`traffic_logs`；固定复用已有 get_security_rules/get_wildfire_status/get_content_versions/get_traffic_logs 工具，透传 firewall、signal；traffic_logs 复用设备时钟窗口与 1000 上限，返回 `{window,count}` 并与已有 threat_logs 共享缓存。

- [x] 写正常/风险/缺失、字符串与数组 member、显式 disabled、空规则/未知形状、WildFire 未识别文本、内容版本无新旧证据、无日志不等于中断、设备窗口错误等 fixture。示例：`assert.ok(check.evaluate({}).some(x => x.severity === 'unknown'))`。
- [x] `node --test webui/test/monitor-compliance.test.js` 确认 RED。
- [x] 实现固定来源、纯规则和数组装配：`const checks = definitions || [...basicChecks, ...deviceChecks, ...networkChecks, ...securityChecks, ...complianceChecks]`。版本仅观察信息；缺少发布时间或最新版本基准则 freshness 为 unknown；日志仅说明窗口内观察证据，不能宣称完整连续性。
- [x] 同命令及 adapter 测试 GREEN；报告来源、规则边界、未支持情况。完整 findings 保持现有脱敏、风险优先截断惯例。

### Task 2: 单一执行与报告来源

Files: `webui/services/monitor/{request,report}.js`, `webui/services/{task-planner,task-service}.js`, `webui/app.js`, `webui/routes/api-routes.js`, focused tests。

- [x] RED：`assert.deepEqual(parseMonitorRequest('完整巡检 基础'), parseMonitorRequest('深度健康巡检 基础'))`；所有固定别名分发 monitor，LLM 返回旧 inspect 但范围不明确时仍 MONITOR_INPUT；历史 inspect 恢复不变。
- [x] request 前缀增加完整巡检/巡检/inspect；新增四项 ID/中文名称；ACTIONS 移除 inspect；移除 planner inspect dispatch、Task Service runInspect 与 inspectReportWriter。
- [x] RED：`service.getMonitorReportNotification({taskId: 7}).taskId === 7`；指定旧任务返回 null；默认选择最新已结束 monitor；无报告返回 null；摘要包含部分状态、覆盖缺口、设备、任务 ID、风险并明确省略。
- [x] report 导出 `formatMonitorNotification(taskId, report)`；Task Service 返回 `{taskId, text}`；Router POST push-report 解析可选 taskId，调用唯一 Task Service 方法后 send，不读取磁盘旧报告。成功响应附 taskId；非法 ID 400、指定无报告 404、无最新报告 400，GET 不发送。
- [x] 集成测试以捕获发送替身验证摘要内容与同 ID 的 JSON 导出一致；认证前置保留。更新旧 API 测试契约。

### Task 3: 统一入口和旧历史展示

Files: `webui/index.html`, `webui/assets/monitor-ui.js`（仅必要处）, `webui/test/monitor-unified-ui.test.js`。

- [x] RED：提取菜单/概览 onclick 与快捷按钮列表，确认所有新入口只填或发送深度健康巡检，快捷列表无 inspect；旧历史渲染仍保留 rate/checks 分支。
- [x] 修改左侧文案和提示、概览快捷、默认任务提示、快捷列表；不改按钮原来的“填入”与“立即发送”交互差别。旧 inspect 报告标为“历史完整巡检报告”，不重算。
- [x] 报告中增加显式“推送此报告到飞书”按钮，复用既有 fjs/提示；POST body `{taskId}`。不自动发送；设置中的最新推送改文案避免旧合规称呼。
- [x] GREEN；真实页面模拟点击入口、旧历史、新报告指定推送、下载和窄屏，发送替身仅在隔离测试服务。

### Task 4: 删除验证、运行验证与文档

- [x] 更新测试中的默认目录数量为实际 33，保留原基础 8；新旧报告 schema 兼容，不修改旧 29 项报告。
- [x] `node --test webui/test/*.test.js` 全量通过；`rg 'runInspect|inspectReportWriter' webui` 无执行引用；独立复核。
- [x] 核实活动任务为零、备份当前运行数据、不清理历史；安全重启当前 canonical 服务；认证、目录、旧/新任务只读验证；运行一次真实全量只读巡检，并验证重启恢复和导出。
- [x] 中文说明记录合并内容、数据口径、实际支持度、测试和限制；仅暂存本次文件及 index.html 自有片段，隔离暂存快照回归，通过后本地提交，不推送。

## Progress

- Task 1–3：已实现，独立规则复核 127/127 通过；执行链/UI 复核通过。两处 P2 边界误判已 RED→GREEN 修复。
- Task 4：全量 265/265，隔离暂存快照 263/263；桌面/窄屏浏览器验证通过；实际 33 项报告及取消报告在重启后原样恢复，导出与摘要一致。
- 飞书桥接扩展：自动回执改为 GET 同一报告摘要，monitor 等待上限 660 秒，其他任务维持 90 秒；离线验证通过，运行中的旧目录 bridge 切换需用户确认，未发送真实飞书消息。
- 基线版本 5b80d3e；只提交本次整合代码和文档，不推送。原有未提交登录/认证及运行时变更保留。
