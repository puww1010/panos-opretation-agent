# Feishu CLI Runtime Fix

> **For agentic workers:** Use executing-plans for this single scoped repair, with test-first verification and an independent review. Work in the existing canonical checkout, as the user requested; no second service directory.

**Goal:** 修复当前控制台发送飞书消息时的 `spawn lark-cli ENOENT`，不发送真实测试消息。

**Architecture:** 在 `webui/lib/feishu-runtime.js` 解析 CLI 和子进程环境；`app.js` 的既有发送函数仍负责调用。优先显式 LARK_CLI，然后 PATH，再检测用户目录已有的可执行 WorkBuddy CLI；均不存在时保留可选功能的原始命令名，不安装依赖。飞书子进程 PATH 加入当前 Node 和已解析 CLI 的目录，不修改全局 PATH。

**Tech Stack:** Node.js 原生 fs/path/os/child_process、node:test；不引入依赖。

## Constraints

- 不读取或输出认证值，不提交运行时配置；保留原有未提交登录/认证修改。
- 不更换机器人身份或群；230002 是另一个权限问题，不绕过它。
- 不主动发送真实消息、不创建防火墙任务；旧桥接后台暂不切换。
- 仅在活动任务为零、备份任务和会话后重启 8080。只提交本次文件，不推送。

## Task 1: CLI 定位与独立子进程环境

Files: create `webui/lib/feishu-runtime.js`, `webui/test/feishu-runtime.test.js`; modify `webui/app.js`.

Interface: `resolveFeishuRuntime({ environment = process.env, homeDirectory = os.homedir(), nodeExecutable = process.execPath } = {}) => { cli, env }`。

- [x] RED：显式配置优先、PATH 优先于备用安装、已有备用安装可识别、非可执行/目录不选、缺少工具不阻止控制台启动、输入环境不被修改；空 PATH 下启动真实 `#!/usr/bin/env node` 的本地假 CLI。
- [x] 实现：候选使用 `accessSync(X_OK)` 和 `statSync().isFile()`；返回 `{ cli, env: { ...environment, PATH: [dirname(nodeExecutable), isAbsolute(cli) ? dirname(cli) : '', environment.PATH].filter(Boolean).join(path.delimiter) } }`。
- [x] `app.js` 用 `resolveFeishuRuntime()` 得到 LARK_CLI，移除原飞书全局 PATH 修改，给既有 `execFile` 传 `env: feishuRuntime.env`。
- [x] GREEN：`node --test webui/test/feishu-runtime.test.js`，全量 `node --test webui/test/*.test.js`；独立复核。
- [x] 安全重启并检查 `/api/feishu/status` 返回已存在的绝对 CLI 路径；用同一程序及子进程环境做只读群消息查询，区分启动成功和群权限失败。不通过真实发送接口验收。
- [x] 更新中文说明，明确实际飞书投递未验收及旧后台状态。
- [x] 独立本地提交，仅纳入本次修复文件与文档，不推送。

## Verification evidence

- 初次测试在实现文件尚不存在时失败，随后 8/8 通过；应用发送函数验证中移除子进程环境后会失败，证明能检出核心回归。
- 全量 273/273；排除用户原有未提交变更的拟提交快照 271/271，均无跳过、取消或失败。
- 独立只读复核通过，未发现 Critical / Important 问题。
- 重启前无活动任务；受限备份位于 `/Users/vpeng/Library/Application Support/PANOSConsole/backups/feishu-runtime-e158eK/`，未纳入 Git。
- 重启后 8080 监听 PID 89622，CLI 绝对路径已加载，任务列表与认证文件不变，认证与首页 200、未认证任务 401、idleMinutes 为 10。
- 实际只读查询：CLI 已启动，飞书返回 230002；机器人群权限待处理，未发真实消息，旧后台未切换。
