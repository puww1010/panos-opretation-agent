# PAN-OS 深度巡检 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将已批准的三批深度健康巡检原生接入现有控制台。

**Architecture:** Task Planner 分发 monitor；Task Service 注入独立巡检服务并持久化结果。固定采集目录通过现有 Adapter/MCP 读取，纯规则评估，UI 使用结构化报告。

**Tech Stack:** 当前 Node.js CommonJS、node:test、原生页面、现有 MCP；不新增 Python/服务/数据库。

## Global Constraints

只读；保留原有未提交改动；禁止密钥和原始异常落盘；所有状态归 Task Service；固定命令白名单；未知不当正常；MP/DP 分开；不使用 LLM 判定告警；不添加定时任务；所有新路径先测试后实现。

## Task 1：检查契约和基础八项

Files: `webui/services/monitor/{helpers,basic-checks}.js`, `webui/test/monitor-basic.test.js`。
Interface: `basicChecks` 数组，每项 `{id,category,label,sources,evaluate(data, context)}`。data 按 sourceId 映射已解析的 PAN-OS result；context `{now,minutes}`。evaluate 返回 findings 数组；单 finding `{metric,value,unit,severity,message,recommendation}`，可附 plane/window。`helpers.js` 提供有限树字段检索、entry 列表和严格数值转换（空值返回 null）、finding 构造；不接受未知数据为健康。

- [x] 写 source 数据 fixture 测试，八项含正常/风险/缺失；CPU 不把 load 当百分比，HA 明确 disabled 不报警，未用端口 down 不当故障。
- [x] `node --test webui/test/monitor-basic.test.js` 验证 RED。
- [x] 编写独立规则模块；不修改其他任务文件。
- [x] 同一命令验证 GREEN，审查字段来源和缺失语义。

## Task 2：受控采集与巡检执行服务

Files: `webui/services/monitor/{sources,service}.js`, `webui/adapters/panos-adapter.js`, `webui/test/monitor-service.test.js`, `webui/test/monitor-adapter.test.js`。
Interfaces: `createMonitorService({readSource,clock})` 返回 `run({firewall,checks,category,minutes,signal,onProgress})` 和目录；readSource(sourceId,firewall,{signal,minutes})。run 返回 `{schemaVersion,skillId,skillRevision,executionStatus,overallSeverity,coverage,checks,startedAt,finishedAt,firewall}`；执行去重在 Task Service。adapter 新增 `readMonitorSource`，限定 sourceId，复用既有 MCP 连接/认证，无任意 XML 输入。

- [x] 写未知 source、错误响应、只读白名单、正确 firewall、缺失覆盖、迟到取消、超时测试。
- [x] 运行对应测试观察 RED。
- [x] 实现采集目录、错误分类/脱敏、逐项进度、有界超时；已解析未知字段不自动算成功。
- [x] 运行测试观察 GREEN，保留原有查询传输行为。

## Task 3：Task Service 和自然语言接入

Files: `webui/services/{task-service,task-planner}.js`, `webui/services/monitor/request.js`, `webui/app.js`, `webui/test/monitor-task.test.js`。
Interfaces: `taskService.runMonitor(task)`；`parseMonitorRequest(input)` 返回 null 或 `{checks?,category?,minutes}`；`getMonitorReport(id,format)` 返回 null 或 `{filename,mime,content}`。使用既有 dispatchTask/recordAudit/saveTask/actOnTask。monitor 请求不向变更执行器转发。

- [x] 写手动全量/分类/单项、旧完整巡检不变、创建保存、并发拒绝、取消、恢复与导出测试。
- [x] 运行测试观察 RED。
- [x] 注入服务、固定范围解析、控制器与审计；中断恢复沿用原任务存储。
- [x] 运行测试观察 GREEN，并跑既有任务/路由测试。

## Task 4：剩余二十一项检查

Files: `webui/services/monitor/{device-checks,network-checks,security-checks}.js`, `webui/test/monitor-extended.test.js`。
Interfaces: 与 Task 1 相同；各文件导出检查数组，service 合并为 29 项。来源目录与实现必须一致，文档记录功能兼容性。

- [x] 写每项正常/异常/缺失 fixture、FIN+FAIL、SD-WAN 阈值、威胁窗口截断、空功能/unsupported 测试。
- [x] 运行测试观察 RED。
- [x] 实现针对已知结构的判断，不把未知数据当健康；全局 counter 不杜撰速率，缺基线仅展示采样事实。
- [x] 验证全部 29 项目录唯一、来源固定、测试 GREEN，并复核上游规则差异。

## Task 5：中文 UI、认证导出与帮助

Files: `webui/services/monitor/report.js`, `webui/routes/api-routes.js`, `webui/index.html`, `webui/test/monitor-report.test.js`, `docs/深度健康巡检使用说明.md`。
Interface: GET `/api/monitor/checks` 固定目录；GET `/api/task/:id/monitor/export?format=json|html` 返回 `{filename,mime,content}`，由现有认证前置保护。前端复用 fjs() 下载 Blob，无 token 查询字符串。

- [x] 写格式、权限、非法任务、HTML 转义、缺失证据说明测试，观察 RED。
- [x] 增量加入入口、逐项进度、八分类、异常优先、证据与原始字段展开、两种导出；不改登录页/已有布局。
- [x] 测试 GREEN，浏览器验证桌面/窄屏、展开、下载、取消和控制台错误。

## Task 6：综合验收

- [x] `node --test webui/test/*.test.js`；核对用户原改动未被覆盖。
- [x] 对新增 diff 做独立复核，修复后重跑覆盖测试。
- [x] 只读检查实际运行路径和活动任务，在无活动任务且可安全恢复情况下加载更新；不另建长期运行副本。
- [x] 真实设备按需执行只读检查；逐项报告有效、不适用、不支持、失败，禁止“全部正常”掩盖缺失。
- [x] 文档记录实际测试数、环境、未验证项、保留的原有改动；只提交本任务文件/片段，不推送。

## Progress

- 2026-09-21：基线 74/74 测试通过；原有工作树内容已核对，使用当前项目增量实施。
- Task 1：基础八项 39/39，通过独立复核与真实基础采集；修正硬件/ifnet 重复、DP 核心采样数组、MP CPU 口径与证书读取。
- Task 2：受控采集 7/7、执行服务 7/7；固定只读源、设备时钟窗口、取消、超时、未支持命令、完整 findings 与限量证据分离。
- Task 3：任务集成 6/6；覆盖持久化、审计、互斥、取消、旧模糊去重不能假取消 monitor、大模型分类不能扩大未解析的检查范围或丢弃窗口。保留旧完整巡检。
- Task 4：扩展二十一项 85/85；独立复核通过，针对 PA-440 的 jobs、zone-protection、FQDN、VPN、日志配额格式补充兼容。
- Task 5：报告 4/4、HTTP 2/2；真实浏览器验证登录、创建、报告下载、展开保持、取消和窄屏显示。测试服务使用演示数据，不冒充真实设备。
- Task 6：全量 224/224；真实 8080 任务 #17 完成 29 项采集、两种导出与重启恢复。结果为部分完成：13 有效、5 部分、2 不适用、5 不支持、4 未知、0 错误，覆盖率 52%。详见中文使用说明。
- 发布：用户选择保留当前 8080 的任务/登录会话；两边数据已独立备份，代码和服务切换到唯一项目。新服务以独立后台进程运行。macOS 登录自启仍受 Documents 访问权限限制，未伪称修复；原目录未删除。
- 提交边界：仅纳入本次监控代码、测试、文档与 index.html 的监控片段；原登录页、空闲认证、运行时数据和其他原有改动不混入提交，不推送 GitHub。
