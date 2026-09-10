# WebUI 架构变更与前后对比（五阶段完成版）

| 项 | 内容 |
|---|---|
| 更新日期 | 2026-08-30 |
| 适用范围 | `webui/` 控制台内部试用版，以及本地 PAN-OS MCP 集成 |
| 架构改造状态 | 五个增量阶段均已完成 |
| 最后相关提交 | `0114b29 fix: reuse keychain credential for direct panos calls` |
| 运行策略 | 内部测试保持 `IDLE_MINUTES = 0`，不启用无操作自动退出 |

## 1. 结论

五个既定架构阶段已经全部完成。原先由 `webui/server.js` 集中承担的 HTTP 路由、认证、LLM、PAN-OS/MCP 通信、任务状态机、候选配置、提交、审计、Dashboard 和静态资源处理，现已按职责拆到 Adapter、Service、Router 和纯函数库中。

现在的 `webui/server.js` 只保留进程入口：创建应用、监听端口、启动 MCP 连接。它不再直接调用 PAN-OS/MCP、不再处理任务生命周期、不再组装 LLM 提示词、不再维护任务或审计状态，也不再处理 HTTP 路由。

本次改造没有改用 Web 框架或重写产品；是在保留原生 Node.js HTTP、现有 API 路径、候选后提交安全机制和内部试用行为的前提下，完成一次可测试、可定位问题的职责拆分。

## 2. 改造前后对比

### 2.1 改造前：`server.js` 是单体“上帝模块”

```text
浏览器 / 飞书
      │
      ▼
webui/server.js
  ├─ 静态资源、首页、404 与全部 HTTP 路由
  ├─ 登录认证、会话与安全响应头
  ├─ MCP 子进程启动与工具调用
  ├─ PAN-OS 直接 HTTPS / XML 调用
  ├─ LLM 配置、选择、提示词、意图解析与日志
  ├─ 任务创建、状态流转、候选规则、审批、取消与提交
  ├─ tasks.json / audit-events.json 的读写和恢复
  ├─ 查询、巡检、审计、威胁与连通性诊断
  ├─ Dashboard、拓扑、指标和历史聚合
  └─ 飞书状态、消息和报告推送
```

这种结构能够运行，但任何一条业务链的变动都容易影响其他职责：

- 修复防火墙 API、任务执行或页面路由时，都需要改同一个超大入口文件；
- 任务状态、审计和 HTTP 响应可能由不同代码段分别维护，难以保证一致；
- 单独测试 LLM、PAN-OS 通信或 Dashboard 时会连带启动无关逻辑；
- 新旧分支容易并存，出现“代码看似迁移、实际仍从旧入口执行”的风险；
- 故障定位会混淆 WebUI 会话认证、MCP 连接和 PAN-OS API 认证这三类不同问题。

### 2.2 改造后：明确的分层和唯一职责入口

```text
浏览器 / 飞书
      │
      ▼
webui/server.js                         进程入口（9 行）
      │ createApplication()
      ▼
webui/app.js                            依赖装配与原生 HTTP 请求顺序
  ├─ 静态资源 Router
  ├─ Auth Router
  ├─ Dashboard Router
  ├─ LLM Router
  ├─ Task Router
  └─ Operations Router（防火墙 / 飞书）
      │
      ├───────────────┬───────────────┬────────────────┬──────────────┐
      ▼               ▼               ▼                ▼              ▼
PAN-OS Adapter   Task Service     LLM Service    Dashboard Service  Auth Service
      │               │               │                │              │
      ▼               ▼               ▼                ▼              ▼
PAN-OS/MCP       任务+审计持久化     提示词/模型        概览/拓扑/指标   会话/密码
```

### 2.3 责任边界对比

| 领域 | 改造前 | 改造后 | 收益 |
|---|---|---|---|
| 进程启动 | `server.js` 同时启动并承担业务 | `server.js` 仅创建应用、监听端口、连接 MCP | 入口可读、启动问题和业务问题分离 |
| 应用装配 | 隐含在单体逻辑中 | `app.js` 明确构造依赖并确定请求顺序 | 依赖可追溯、便于替换模拟对象测试 |
| PAN-OS / MCP | 业务代码直接处理 HTTPS、XML、MCP | `panos-adapter.js` 统一承担传输 | 业务层无需理解连接和 XML 细节 |
| 任务与审计 | 路由、执行器和全局数组共同维护 | `task-service.js` 是唯一状态变更与持久化入口 | 状态、审计、恢复不再分散 |
| LLM | 入口文件直接拼装配置、提示词和结果 | `llm-service.js` 统一管理 | 模型切换、上下文、日志可独立验证 |
| Dashboard | 路由层直接拼接设备数据 | `dashboard-service.js` 聚合只读视图 | Dashboard 逻辑可缓存、可单测 |
| HTTP 路由 | 大量 `if/else` 混在业务内 | `api-routes.js`、`static-routes.js` 分组处理 | HTTP 契约与业务实现解耦 |
| 认证 | 与路由、页面处理交织 | `auth-service.js` 管理认证事实，Router 管理 HTTP 映射 | 避免认证顺序抢占登录与静态资源 |

## 3. 当前模块结构

```text
webui/
├── server.js                         进程入口
├── app.js                            应用装配、依赖注入、原生 HTTP 调度
├── adapters/
│   └── panos-adapter.js               MCP 与 PAN-OS 直连传输
├── services/
│   ├── task-service.js                任务、候选、提交、审计、诊断、持久化
│   ├── task-planner.js                输入规划、会话分组、去重、变更预览
│   ├── llm-service.js                 LLM 配置、选择、提示词、分类、摘要
│   ├── dashboard-service.js           概览、指标、拓扑、历史
│   └── auth-service.js                登录、会话、密码变更、空闲策略
├── routes/
│   ├── api-routes.js                  Auth、Dashboard、LLM、Task、飞书等 API
│   └── static-routes.js               首页、静态资源与路径边界
├── lib/
│   ├── security.js                    安全响应头、同源 API 规则
│   ├── task-governance.js             任务状态转移和计划指纹
│   └── health.js                      Dashboard 健康摘要纯函数
└── test/                              对应服务与 Router 的回归测试
```

`app.js` 是组合根（composition root）：它负责创建对象、注入协作依赖、保留既有请求顺序和少量部署适配（例如飞书桥）。它不是新的业务执行入口；业务规则仍分别落在专属 Service、Adapter 或 Router 中。

## 4. 五个阶段完成情况

| 阶段 | 目标 | 完成内容 | 关键提交 |
|---|---|---|---|
| 第 1 阶段 | PAN-OS Adapter | MCP 生命周期、工具调用、直连 HTTPS/XML、配置读写、提交和工具路由收口 | `2b13585`、`0f25b24`、`0114b29` |
| 第 2 阶段 | Task Service | 任务状态机、候选执行、批量选择、提交轮询、查询/巡检/审计/诊断、任务和审计持久化 | `4ccee86` 至 `0641ba5` |
| 第 3 阶段 | LLM Service | 模型配置与选择、上下文、意图解析、查询摘要、诊断综合、日志 | `77ccd3b`、`1562e19`、`23d00e0`、`7765495` |
| 第 4 阶段 | Dashboard / Auth / Router Layer | Dashboard、认证、LLM、任务、飞书、防火墙、静态资源与 404 路由分组；旧路由分支清理 | `72cef06`、`c777a1c`、`f711205`、`bf24c02`、`82146da` |
| 第 5 阶段 | 入口装配和最终清理 | Task Planner、`createApplication()`、薄 `server.js`、完整验证和真实只读防火墙检查 | `987dd7a`、`03d7b28`、`0114b29` |

### 4.1 第 1 阶段：PAN-OS Adapter

对应文件：`webui/adapters/panos-adapter.js`。

Adapter 统一封装 MCP 子进程启动与工具调用、PAN-OS `op`/`config`/`commit` 操作、直连与 MCP 工具路由、日志深度查询、XML 解析及结果整理。业务层通过 Adapter 的公开能力访问防火墙，而不再自行拼装 HTTPS 请求。

本阶段解决了 `path is not defined` 导致 MCP 初始化失败的问题（`0f25b24`）。在最后验收中还修复了密钥迁移后的直连认证断层：API 密钥已安全迁移到系统钥匙串，JSON 配置不再保存明文密钥；Adapter 现在从同一钥匙串服务按防火墙名称读取直连凭据。这样不恢复明文配置，也不会把密钥写入日志或提交记录。

### 4.2 第 2 阶段：Task Service 与持久化边界

对应文件：`webui/services/task-service.js`。

Task Service 成为任务状态、审计和持久化的唯一入口，覆盖：

- 创建、恢复、读取、清理和去重任务；
- 审批、拒绝、取消、候选规则选择、批量选择与子任务编排；
- 地址对象、规则移动、规则启停/删除、单 IP 封禁/放行、IP 组封禁；
- candidate → approval → commit 的安全执行流程；
- commit job 成功、失败、取消、超时和人工跟进场景；
- 查询、完整巡检、审计、通用诊断、威胁画像和连通性诊断；
- `cfgs/tasks.json` 与 `cfgs/audit-events.json` 的加载、保存和重启恢复。

任务状态和审计事件不再由 Router 或 `server.js` 分别写入，因此不会发生“任务已变更但没有审计”或“审计写入成功但任务未持久化”的职责断裂。

### 4.3 第 3 阶段：LLM Service

对应文件：`webui/services/llm-service.js`。

LLM 相关职责已移出入口文件，包括 Provider 配置的公开视图、保存、删除与选择，当前模型持久化恢复，多轮任务上下文和意图分类，查询结果摘要与诊断结论综合，以及有界的 LLM 决策日志。凭据不出现在公开 API 返回或测试输出中。

`task-planner.js` 负责将用户输入、会话上下文、动作定义与变更模板组合成任务计划；它不直接修改任务状态，最终仍由 Task Service 执行。

### 4.4 第 4 阶段：Dashboard、认证与 Router Layer

对应文件：`webui/services/dashboard-service.js`、`webui/services/auth-service.js`、`webui/routes/api-routes.js`、`webui/routes/static-routes.js`。

完成内容：

- Dashboard 的设备概览、健康摘要、拓扑、指标窗口和任务历史归入 Dashboard Service；
- 登录、登出、会话检查、保持会话和密码修改归入 Auth Service；
- Dashboard、LLM、Task、飞书、防火墙列表、Auth API 由 API Router 分组分发；
- 首页、静态资源、favicon 和 404 由 Static Router 统一处理；
- 请求顺序固定为：静态资源 → Auth → Dashboard → LLM → Task → Operations → 404；
- Router 只解析 HTTP、保留状态码和响应格式，不直接改任务状态或调用 PAN-OS。

这解决了此前“新 Router 已接管但 `server.js` 仍物理保留旧分支”的维护风险；目前旧 Dashboard、LLM、Task 路由实现已删除，不再依赖不可达分支。

### 4.5 第 5 阶段：应用装配与入口收口

对应文件：`webui/app.js`、`webui/server.js`、`webui/services/task-planner.js`。

完成内容：

- 把任务输入规划、会话分组、去重与变更预览抽到 Task Planner；
- 将对象构造和依赖注入归入 `createApplication()`；
- 将 HTTP 请求调度归入可测试的 `createApp()`；
- 将 `server.js` 缩减为创建应用、监听端口、连接 MCP 的薄入口；
- 删除因旧单体入口遗留的实现与导入；
- 保持新地址对象预览的默认类型正确，不再出现 `undefined`。

第 5 阶段的完成标准是“`server.js` 不再拥有任何领域业务”，而不是机械追求每个字面常量都离开 `app.js`。当前 `app.js` 作为明确的组合根保留部署配置和协作者装配，符合原设计边界。

## 5. 安全与运行行为保持项

本次改造特意没有改变以下内部试用版行为：

- `IDLE_MINUTES = 0`：无操作 15 分钟不会被强制重新登录；
- 任务变更仍执行“候选配置 → 审批 → 确认提交”的安全流程；
- 计划指纹仍用于发现审批前的计划内容漂移；
- 所有 `/api/*` 继续需要认证；飞书桥使用独立内部令牌；
- API 密钥不写回 `cfgs/firewalls.json`，由系统钥匙串保管；
- 未引入数据库、消息队列、Web 框架或新的运行时依赖；
- 保持 CommonJS 与原生 Node.js HTTP 的现有部署方式。

用户管理的运行时文件不属于架构源码提交范围，仍保持原有状态：

- `cfgs/llm-choice.json`
- `cfgs/tasks.json`
- `webui/index.html`

## 6. 最终验收证据

| 验收项 | 结果 |
|---|---|
| WebUI 全量 Node 测试 | 61 / 61 通过 |
| PAN-OS MCP 测试 | 109 / 109 通过 |
| PAN-OS MCP TypeScript 构建 | 通过 |
| Adapter 凭据迁移回归 | 通过；验证直连请求使用钥匙串提供的测试凭据 |
| Git diff 格式检查 | 通过 |
| 本地服务重启前任务检查 | 无 `running`、`executing`、`committing` 任务 |
| 本地服务 | 已重启并监听 `http://localhost:8080` |
| 认证状态 | 当前已认证 WebUI 会话可正常加载 |
| 真实非生产防火墙只读检查 | 系统资源、活动会话、HA 状态均成功，无 403 |
| Dashboard 页面检查 | 已显示设备型号和会话容量；未出现“未获取到设备数据”或数据面离线提示 |
| 配置写入 | 未创建 candidate，未提交防火墙配置 |

## 7. 已解决问题清单

| 问题 | 原因 | 解决方式 |
|---|---|---|
| MCP 初始化报 `path is not defined` | Adapter 缺少 Node.js `path` 导入 | 补齐依赖并增加连接回归测试 |
| 连通性诊断报 `path is not defined` | 旧路径依赖与迁移后模块边界不一致 | 修复引用并将诊断执行器迁入 Task Service |
| 任务、审计和重启恢复归属分散 | `server.js` 与执行器共同维护状态 | Task Service 成为唯一持久化与审计入口 |
| Router 迁移后旧分支仍留存 | 新旧 HTTP 分发共存 | Router 覆盖后删除旧 Dashboard、LLM、Task 分支 |
| 设备状态任务出现 API 403 | 明文密钥迁入系统钥匙串后，直连 Adapter 未复用凭据 | Adapter 从同一钥匙串读取密钥；真实只读调用已验证 |

## 8. 完成后的维护原则

后续新增能力应遵循当前边界：

1. PAN-OS/MCP 新传输能力放入 Adapter；
2. 会改变任务状态、审计或持久化的能力放入 Task Service；
3. 模型、提示词、上下文与文本总结放入 LLM Service；
4. 只读概览、指标和历史放入 Dashboard Service；
5. HTTP 请求解析、认证前置和响应码映射放入 Router；
6. `app.js` 只装配依赖，`server.js` 保持薄入口；
7. 修改前先补充对应模块边界测试，修改后跑全量 WebUI 与 MCP 测试；
8. 未经明确授权，不通过任务或脚本创建候选配置、写入防火墙配置或执行 commit。

## 9. 当前状态

五个架构阶段均已完成，并经代码测试、服务重启和非生产防火墙只读验证。当前没有必须完成的架构迁移尾项。

后续工作属于新功能、体验优化或正式生产化准备，而不是本轮架构拆分的未完成项。正式生产前仍应单独评估空闲会话策略、SSO/角色权限、密钥轮换、审计保留周期和高可用部署；这些不应与已经完成的内部试用版架构改造混为一谈。
