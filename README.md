# 防火墙监控运维控制台

面向内部网络运营团队的 PAN-OS 运维控制台：把设备概览、网络拓扑、流量分析、深度健康巡检、诊断与变更审批放在同一个任务中心。采用原生 Node.js HTTP、分层业务服务与本地 MCP，通过 PAN-OS API 读取设备数据；可选接入大模型和飞书。

> **版本范围（2026-09-28）**：功能基线 `bcb070a` 已通过 PR #2 合入 `main`（合并提交 `bfd4b2b`），包含五阶段职责拆分、原生深度巡检和巡检一键执行。当前交付方式是源码部署，**尚未发布经过最新版验收的 DMG / EXE 安装包**。

[安装与运行](docs/DEPLOY.md) · [架构重构与前后对比](docs/ARCHITECTURE.md) · [深度巡检说明](docs/深度健康巡检使用说明.md) · [打包状态](docs/PACKAGING-DEPLOY.md) · [维护与发布](docs/GITHUB-RELEASE.md)

## 核心能力

| 能力 | 当前实现 |
| --- | --- |
| 运营概览 | 设备、HA、会话、许可、接口与 MP/DP 资源；注明采样和估算口径 |
| 网络拓扑 | Zone 分区、语义缩放、节点详情抽屉及真实状态叠加；不是完整网络自动发现系统 |
| 统一任务中心 | 查询、深度巡检、诊断、审计与变更审批；进度、取消、历史以及原始问题的修改、复制、重发 |
| 深度健康巡检 | 33 项检查、8 个分类；侧栏及快捷入口一键执行；支持分类/单项、覆盖率与缺失证据说明 |
| 统一巡检报告 | 页面、JSON/HTML 导出与飞书摘要读取同一份持久化报告；兼容旧 `inspect` 历史 |
| 流量分析 | 默认最近 10 分钟，最多读取 1000 条、持久化 50 条预览；已读取集合的趋势、Top 统计、分页与导出 |
| 变更治理 | 候选选择、批量子任务、审批、确认 commit、状态校验、计划指纹及独立审计 |
| 模型与飞书 | 模型配置/选择、摘要与诊断综合；可选飞书消息发送、巡检摘要及 Python 消息桥接 |

**边界**：达到日志读取上限不等于完整覆盖时间窗；任务“完成”不等于所有工具成功或设备完全健康。深度巡检分别呈现采集状态、风险和覆盖率，不把不支持、未配置与真实异常混为一谈。

## 架构已经怎样重构

此前 `webui/server.js` 同时负责 HTTP、认证、模型、设备通信、任务执行与持久化。现在它只负责创建应用、监听端口和发起 MCP 连接，业务分别归属：

| 模块 | 职责 |
| --- | --- |
| `webui/app.js` | 创建服务、注入依赖、确定 HTTP 处理顺序；仍保留动作/变更模板元数据和飞书接线 |
| `webui/routes/` | 静态资源、认证前置及 Dashboard / LLM / Task / Operations 路由；不自行改任务状态 |
| `webui/services/task-planner.js` | 解析用户请求、识别确定性巡检指令、规划任务 |
| `webui/services/task-service.js` | 任务生命周期、执行器、候选/提交、批量编排，以及任务/审计存储的唯一业务入口 |
| `webui/services/monitor/` | 固定只读采集、检查规则、超时、覆盖率及统一报告，不运行上游 Python skill |
| Auth / Dashboard / LLM Service | 分别管理认证会话、概览拓扑指标、模型配置和推理 |
| `webui/adapters/panos-adapter.js` | MCP 子进程、工具路由和 PAN-OS 直接 HTTPS/XML 通信 |

这是**分层单体**，不是微服务重写：一个 Web 后端加一个本地 MCP 子进程，飞书桥接可选。详细调用链、数据归属、五阶段结果及剩余限制见 [架构说明](docs/ARCHITECTURE.md)。

## 安装前准备

| 项目 | 要求 |
| --- | --- |
| Node.js | ≥22.19.0；当前验证基线为 Node 22.x |
| npm / Git / Bash | 安装依赖、获取源码；现有启动脚本使用 Bash |
| 网络与设备 | 安装机器能访问防火墙管理 API；提供自己的 PAN-OS API 凭据，变更另需相应权限 |
| LLM（可选） | 自行配置提供方、实际可用模型和密钥；固定深度巡检不依赖 LLM |
| 飞书（可选） | 安装并认证 `lark-cli`；接收群消息另需 Python 3 与桥接配置 |

主程序不要求安装 WorkBuddy，但**不是零依赖程序**。WebUI 依赖 MCP SDK；MCP 另有 XML、HTTP、代理、校验和系统密钥链组件。详见 [依赖清单](docs/DEPLOY.md#2-依赖与安装)。

## 从源码开始

```bash
git clone --branch main --single-branch \
  https://github.com/puww1010/panos-opretation-agent.git
cd panos-opretation-agent
npm install --prefix webui --omit=dev --ignore-scripts
npm install --prefix mcp/panos-mcp --omit=dev --ignore-scripts
```

随后按 [安装手册](docs/DEPLOY.md#3-首次配置与启动) 创建自己的防火墙配置、通过隐藏输入初始化管理员密码，再执行 `bash webui/start.sh`。默认浏览器地址为 `http://localhost:8080`。

- 两个目录的依赖都要安装。当前直接运行 MCP TypeScript 源码，不要求先生成 `dist/`；上述命令跳过安装生命周期脚本，避免触发 `prepare` 编译。
- 当前没有提交依赖锁文件，全新克隆不能直接使用 `npm ci`，依赖解析并非完全可复现。
- 不要复制开发机整个目录或跨平台复用 `node_modules`；不要复用他人的密钥、会话或任务记录。
- `standalone/` 是早期独立实现，**不是当前完整功能版的安装入口**。

## 数据、安全与部署限制

- 配置、任务与审计以本地 JSON 保存，无需外部数据库；任务存储使用写队列和临时文件替换，不支持多实例共享写入。
- 重启后可读历史；执行中的任务标记为中断，不自动重做变更。流量原始明细只在内存，重启后需重新查询；深度巡检报告随任务持久化。
- 登录页面与静态资源公开可访问，业务 API 要求认证。WebUI 会话、MCP 连接和防火墙 API 认证是不同边界。
- **本分支已提交的认证代码为 `idleMinutes: 0`，会话最长 7 天**。维护者本机的 10 分钟无操作退出与新版登录页仍有独立未提交改动，不属于本次文档发布。
- 当前 HTTP 监听未显式限定为回环地址；部分 PAN-OS 直连跳过证书验证。不要直接暴露公网，生产部署另需 TLS、访问控制、会话策略与凭据存储评审。
- LLM 和飞书会接收必要任务上下文或报告摘要；启用前确认数据使用与群成员范围。
- 云主机不能直接访问本地私网防火墙；先落实网络连通性，不应公开防火墙管理口。

禁止向 GitHub、公开安装包、日志或截图加入密码、API Key、会话令牌或完整运行时配置。`cfgs/tasks.json` 和 `cfgs/llm-choice.json` 虽匹配忽略规则，仍有历史跟踪；`.gitignore` 不会自动撤销跟踪，提交时必须检查清单。

## 开发与验证

在项目根目录执行：

```bash
node --test webui/test/*.test.js
```

覆盖 Router 契约、任务状态/恢复、变更审批、LLM、Adapter、巡检规则、报告和 UI 入口等。自动测试不代表真实设备全功能验收。真实环境先验证登录、概览和任务列表，不在安装检查中写防火墙配置或发送飞书消息。

## 文档与来源

- [架构重构与前后对比](docs/ARCHITECTURE.md)
- [安装、认证与排障](docs/DEPLOY.md)
- [深度巡检检查目录、统一报告与兼容性](docs/深度健康巡检使用说明.md)
- [安装包现状](docs/PACKAGING-DEPLOY.md)
- [项目交接](docs/PROJECT_HANDOVER.md) · [GitHub 发布](docs/GITHUB-RELEASE.md)
- [五阶段历史详细记录](docs/architecture-stage-1-2-summary.md)

监控目录和部分规则参考 [panos-monitor](https://github.com/puww1010/panos-monitor)，已原生实现，见 [第三方声明](docs/third-party/panos-monitor-NOTICE.md)。设备工具相关来源包括 [Palo-MCP](https://github.com/apius-tech/Palo-MCP) 和 [pan-os-mcp](https://github.com/zm1990s/pan-os-mcp)。子项目保留各自许可声明；正式分发前需核对完整许可与依赖清单，不能仅凭旧 README 的“MIT”视为所有组件已完成许可核对。
