# PAN-OS 防火墙管理 Agent — 部署与运维手册

| 项 | 值 |
|---|---|
| 版本 | v1.0 |
| 日期 | 2026-08-19 |
| 目标设备 | PA-440 @ 192.168.0.250 (PAN-OS 11.2.4-h7) |

## 1. 架构总览

```
用户(WorkBuddy 对话)
  │
  ├─ Skill: panos-firewall-readonly   (P0 只读查询)
  ├─ Skill: panos-firewall-write      (P1 写操作 8 步闭环)
  ├─ Skill: panos-compliance-audit    (P2 合规巡检 8 项基线)
  ├─ Skill: panos-log-analysis        (P2 日志深度分析)
  ├─ Skill: panos-incident-response   (P2 封禁/回收模板)
  │
  └─ MCP: panos (apius-tech/Palo-MCP, 本地源码运行)
       │  117 工具 (R70/W46/A1)
       └─ PAN-OS XML API → PA-440 @ 192.168.0.250
```

## 2. 组件清单

| 组件 | 位置 | 说明 |
|---|---|---|
| MCP server 源码 | `/Users/vpeng/.workbuddy/binaries/node/workspace/panos-mcp-local/` | apius-tech/Palo-MCP v1.3.29，import 已改 .ts |
| 设备配置 | `~/.config/panos-mcp/firewalls.json` | 多设备清单（name/host/api_key） |
| WorkBuddy MCP 配置 | `~/.workbuddy/mcp.json` | panos 条目，本地启动 |
| 启动脚本 | `/Users/vpeng/.workbuddy/binaries/node/workspace/start-panos.sh` | 一键启动（自检+清代理） |
| Skills | `~/.workbuddy/skills/panos-*/SKILL.md` | 5 个能力 skill |
| 报告 | `<workspace>/reports/` | compliance/log-analysis/dashboard/audit |
| 自动化 | PAN-OS 每日合规巡检 (每日 09:00) | automation-1787104486938 |

## 3. 启动与验证

```bash
# 手动启动（stdio，供调试）
~/.../start-panos.sh

# WorkBuddy 接入：Trust ~/.workbuddy/mcp.json 中 panos 条目后重连
# 验证：list_firewalls → get_firewall_info → get_ha_status
```

**排障速查**：
| 症状 | 原因 | 处理 |
|---|---|---|
| Connection closed | 代理劫持 | 检查 env 已清空代理 + NO_PROXY=* |
| TLS 失败 | 代理未绕过 | 同左 |
| 工具未注册 | 需重连/重启 | 连接器页重连或重启 WorkBuddy |
| keychain 警告 | 本机无 keychain | 正常，key 明文存 firewalls.json(600) |

## 4. 多设备接入

1. 编辑 `~/.config/panos-mcp/firewalls.json`：
```json
{ "firewalls": [
    { "name": "pa-440", "host": "192.168.0.250", "api_key": "..." },
    { "name": "fw-2",   "host": "192.168.0.251", "api_key": "..." }
] }
```
2. 连接器页重连 panos
3. 调用时传 `firewall: "fw-2"` 参数；不传则默认第一台

## 5. 安全加固清单（建议按序执行）

| 优先级 | 项 | 操作 |
|---|---|---|
| 🔴 | **API key 轮换** | 当前 key 已明文出现于对话与配置文件。防火墙 Web UI → Device → Administrators → 重新生成 → 更新 firewalls.json |
| 🔴 | **API key 算法** | Setup → Management → Authentication Settings → API Key Certificate（当前 deprecated algorithm） |
| 🟡 | 管理面白名单 | Device → Setup → Management → Permitted IP：仅允许管理网段（如 192.168.0.0/24）访问管理口 |
| 🟡 | 证书校验 | MCP server `verify_ssl` 默认 false；生产建议配 CA 证书后置 true |
| 🟡 | 只读 key | 巡检/查询场景用只读 API key（角色只读），写操作单独用管理员 key |
| 🟢 | 配置文件权限 | `chmod 600 firewalls.json mcp.json`（已执行） |
| 🟢 | 生产网络隔离 | Agent 部署在管理网段，仅 API 出向，防火墙无需出站 |

## 6. 运维手册

**日常**：每日 09:00 自动合规巡检（自动化任务），报告落盘 reports/compliance-YYYY-MM-DD.md

**写操作纪律**（panos-firewall-write）：
- 8 步闭环：申请→预检→审批→candidate→验证→commit 确认→验证→审计
- 高危操作（封禁/删策略）双确认；封禁前必查日志佐证（incident-response）

**常见运维问答**：
- "查策略" → readonly skill → get_security_rules
- "封禁 IP X" → incident-response 模板（方向/时长/双确认）
- "合规怎么样" → compliance-audit
- "这个 IP 什么情况" → log-analysis 归因

## 7. 已知限制

- 本机无 keychain：API key 明文存 firewalls.json（权限 600 缓解）
- 威胁日志断档（6-18 后无新事件）：待排查 Log Settings（未决）
- WildFire 授权未启用：待整改（未决）
- tsc/esbuild 本机易 OOM：源码改动后需在内存充足环境编译或用 strip-types 直跑

## 8. IM 接入（飞书 / 企业微信）

### 8.1 飞书（✅ 已打通：推送 + 读取 + 对话桥接）

**工具**：`lark-cli`（v1.0.88，位于 cli-connector-packages/bin）

**授权 scope（3 次 OAuth，均已授予 Peng Yun）**：
| Scope | 用途 |
|---|---|
| im:chat:read | 列出群聊 |
| im:message.send_as_user + im:message | 发送消息 |
| im:message.group_msg:get_as_user + im:message.p2p_msg:get_as_user + im:message.reactions:read | 读取消息 |

**关键对象**：
- 内网群（可推可读）：`oc_0238b0ea1d6d7a74180cfce85b18cf67`
- 外部群（受租户策略限制，发送报 230027）：`oc_f9801863a7e672b3391dbbdf3b734b77`

**对话桥接**：`<workspace>/feishu-bridge.py`
- 轮询群消息（每 120s，daemon 模式）
- 命中触发词（18 个：防火墙/巡检/查/威胁/策略/状态/NAT/许可/会话/流量/接口/地址对象/区域/VPN/WildFire/内容库/PA-440/PA440）→ 调 WebUI `/api/query` → 摘要回复
- Agent 回复带签名"—— WorkBuddy 防火墙 Agent"防循环
- state 文件：`~/.workbuddy/panos-feishu-last.ts`（去重）

**启动/停止**：
```bash
# 启动（run_in_background 托管）
python3 <workspace>/feishu-bridge.py --daemon
# 停止
pkill -f feishu-bridge.py
```

**验证**（2026-08-19）：
- 推送巡检摘要 ✅（om_x100b67657db524b0c1ca193604d7eec）
- 群发"防火墙状态" → Agent 自动回复设备信息 ✅

**排障**：
| 症状 | 处理 |
|---|---|
| missing_scope | `lark-cli auth login --scope "<scope>"` 重新授权 |
| 230027（外部群） | 改发同租户群，或管理员开放外部群策略 |
| content 非 JSON | 用 `--text "..."` 而非 `--content` |

### 8.2 企业微信（⚠️ 授权完成，企业侧 API 受限待开通）

**工具**：`wecom-cli`（v1.1.0）

**状态**：
- ✅ 机器人授权完成（Bot ID: aibnPycT_EnD-cvNIFJH5Fq7OcIJ_FJinr_，扫码自动获取 Bot ID/Secret）
- ❌ 业务接口报 **errcode 853006**（"this tool is not available for your corporation"）：`chat groups list` 与 `message send` 均不可用

**原因与恢复**（需企业管理员）：
1. 企业未认证 → 管理后台完成企业认证
2. 机器人应用未开通 API 权限 → 应用管理确认"消息发送"权限
3. 接口未申请开通 → 开发者中心申请

**恢复后接入步骤**（wecom-cli 已就绪）：
1. `wecom-cli message send --chat-id <userid/群ID> --msg-type text --text '{"content":"..."}'` 验证发送
2. 参照 feishu-bridge.py 编写 wecom-bridge.py（轮询 `chat messages` → WebUI → 回复）
3. 加入 daemon 托管

## 9. 交接清单（给下一位维护者）

- [ ] 熟悉 5 个 skill 的职责边界
- [ ] 验证每日巡检自动化输出
- [ ] 完成 🔴 安全加固项（key 轮换 + API Key Certificate）
- [ ] 排障速查表可用
- [ ] 飞书桥接 daemon 状态（pkill 后需重启）
- [ ] 企业微信 853006 恢复后补 wecom-bridge
