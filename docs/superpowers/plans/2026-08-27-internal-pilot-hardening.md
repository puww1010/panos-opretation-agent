# 内部试用版安全与运维体验 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改变现有 MCP/PAN-OS 调用语义的前提下，为内部试用控制台增加可测试的安全、任务审计、变更治理与健康总览基础。

**Architecture:** 保持 `webui/server.js` 为 HTTP 入口，把响应头和任务审计/状态转换规则抽成纯 Node 模块。任务执行仍调用现有 MCP 或直连路径，但服务端在调用前验证状态、计划指纹与目标；界面仅展示由 API 返回的状态和审计摘要。

**Tech Stack:** Node.js 22、Node 内置 `node:test`、现有原生 WebUI、MCP SDK、TypeScript/Vitest MCP 子项目。

## Global Constraints

- `IDLE_MINUTES` 保持 `0`；本内部测试版本不实现自动空闲登出。
- 不读取、输出、修改或提交 `cfgs/llm-choice.json`、`cfgs/tasks.json` 中的用户运行时内容。
- 不在测试中连接、修改或 commit 真实 PAN-OS 设备。
- 不引入新的运行时依赖或新的服务进程。
- 每个行为修改必须先有失败测试，再写最小实现。

---

### Task 1: 建立 WebUI 可测试的安全基础

**Files:**
- Create: `webui/lib/security.js`
- Create: `webui/test/security.test.js`
- Modify: `webui/server.js`

**Interfaces:**
- Produces: `buildSecurityHeaders(contentType)`，返回适用于 HTML、JSON 与静态资源的响应头对象。
- Produces: `isSameOriginApiPath(requestUrl)`，仅接受相对 `/api/` 路径。
- Consumes: `server.js` 的统一 `send()` 和静态资源响应逻辑。

- [ ] **Step 1: 编写失败测试，定义安全响应头和 API 路径约束**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSecurityHeaders, isSameOriginApiPath } from '../lib/security.js';

test('JSON API responses receive baseline browser security headers', () => {
  const headers = buildSecurityHeaders('application/json; charset=utf-8');
  assert.equal(headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(headers['X-Frame-Options'], 'DENY');
  assert.equal(headers['Referrer-Policy'], 'same-origin');
});

test('only relative API paths are accepted as same-origin API paths', () => {
  assert.equal(isSameOriginApiPath('/api/tasks'), true);
  assert.equal(isSameOriginApiPath('https://example.test/api/tasks'), false);
});
```

- [ ] **Step 2: 运行测试，确认它因模块不存在而失败**

Run: `node --test webui/test/security.test.js`

Expected: failure reporting `ERR_MODULE_NOT_FOUND` for `webui/lib/security.js`.

- [ ] **Step 3: 实现最小安全模块并在 HTTP 响应中合并其返回值**

```js
function buildSecurityHeaders(contentType) {
  return {
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
}

function isSameOriginApiPath(requestUrl) {
  return typeof requestUrl === 'string' && requestUrl.startsWith('/api/');
}
```

- [ ] **Step 4: 运行单测和本地未认证 API 冒烟检查**

Run: `node --test webui/test/security.test.js && curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/health`

Expected: tests pass; endpoint remains protected with `401` or `404`, never returns a successful unauthenticated device response.

### Task 2: 抽取任务状态转换与不可变审计事件

**Files:**
- Create: `webui/lib/task-governance.js`
- Create: `webui/test/task-governance.test.js`
- Modify: `webui/server.js`

**Interfaces:**
- Produces: `transitionTask(task, action, now)`，返回 `{ ok, task, event }`。
- Produces: `createAuditEvent(task, action, now, details)`，返回只追加的结构化事件。
- Consumes: 现有 `awaiting_approval`、`awaiting_selection`、`awaiting_commit`、`executing`、`done`、`failed`、`cancelled` 状态。

- [ ] **Step 1: 编写失败测试，覆盖允许与拒绝的状态转换**

```js
test('approval moves only an awaiting approval task to executing and records an event', () => {
  const result = transitionTask({ id: 7, status: 'awaiting_approval', audit: [] }, 'approve', 1000);
  assert.equal(result.ok, true);
  assert.equal(result.task.status, 'executing');
  assert.equal(result.event.action, 'approve');
});

test('commit confirmation is rejected before a task reaches awaiting commit', () => {
  const result = transitionTask({ id: 7, status: 'awaiting_approval', audit: [] }, 'confirm', 1000);
  assert.equal(result.ok, false);
  assert.equal(result.task.status, 'awaiting_approval');
});
```

- [ ] **Step 2: 运行测试，确认它因模块不存在而失败**

Run: `node --test webui/test/task-governance.test.js`

Expected: failure reporting `ERR_MODULE_NOT_FOUND` for `webui/lib/task-governance.js`.

- [ ] **Step 3: 实现最小状态表和审计事件，并将现有 approve/reject/cancel/confirm 路由改为调用它**

```js
const TRANSITIONS = {
  approve: { from: ['awaiting_approval'], to: 'executing' },
  reject: { from: ['awaiting_approval'], to: 'cancelled' },
  confirm: { from: ['awaiting_commit'], to: 'committing' },
  cancel: { from: ['pending', 'running', 'executing', 'awaiting_approval', 'awaiting_selection', 'awaiting_commit'], to: 'cancelled' },
};
```

- [ ] **Step 4: 运行状态机测试，并验证非法 API 动作不会进入工具执行函数**

Run: `node --test webui/test/task-governance.test.js`

Expected: all tests pass, including invalid confirmation rejection.

### Task 3: 为变更计划加入计划指纹与审计摘要

**Files:**
- Modify: `webui/lib/task-governance.js`
- Modify: `webui/server.js`
- Modify: `webui/index.html`
- Modify: `webui/test/task-governance.test.js`

**Interfaces:**
- Produces: `planFingerprint({ template, params, firewall })`，返回稳定 SHA-256 指纹。
- Consumes: `runChangeCandidate()` 创建的候选计划和 `runChangeCommit()` 前的任务状态。

- [ ] **Step 1: 编写失败测试，验证相同计划产生相同指纹，目标变化会使指纹不同**

```js
assert.equal(
  planFingerprint({ template: 'disable_rule', params: { name: 'r1' }, firewall: 'fw-a' }),
  planFingerprint({ template: 'disable_rule', params: { name: 'r1' }, firewall: 'fw-a' }),
);
assert.notEqual(
  planFingerprint({ template: 'disable_rule', params: { name: 'r1' }, firewall: 'fw-a' }),
  planFingerprint({ template: 'disable_rule', params: { name: 'r2' }, firewall: 'fw-a' }),
);
```

- [ ] **Step 2: 运行测试，确认指纹函数不存在**

Run: `node --test webui/test/task-governance.test.js`

Expected: failure naming `planFingerprint`.

- [ ] **Step 3: 在候选阶段保存指纹，在 approve/confirm 时重新验证，并向前端返回审计摘要**

```js
if (task.planFingerprint !== planFingerprint({ template: task.template, params: task.params, firewall: task.firewall })) {
  return { ok: false, error: '变更计划已变化，请重新生成候选计划' };
}
```

- [ ] **Step 4: 运行测试，并在 UI 中确认计划显示目标设备、计划指纹短码和最近审计动作**

Run: `node --test webui/test/task-governance.test.js`

Expected: all task-governance tests pass.

### Task 4: 改善总览健康模型与接口信息可读性

**Files:**
- Create: `webui/lib/health.js`
- Create: `webui/test/health.test.js`
- Modify: `webui/server.js`
- Modify: `webui/index.html`

**Interfaces:**
- Produces: `buildHealthSummary(overview)`，返回 `normal`、`attention` 或 `alert` 以及可行动事项数组。
- Consumes: 当前 overview 的许可证、接口、HA、MP/DP 指标。

- [ ] **Step 1: 编写失败测试，验证过期许可证和非预期 Down 接口不能被整体标记为 normal**

```js
const summary = buildHealthSummary({ licenses: { expired: 3 }, interfaces: [{ name: 'ethernet1/5', status: 'DOWN', expectedDown: false }] });
assert.equal(summary.level, 'alert');
assert.equal(summary.items.length, 2);
```

- [ ] **Step 2: 运行测试，确认健康模块不存在**

Run: `node --test webui/test/health.test.js`

Expected: failure reporting `ERR_MODULE_NOT_FOUND` for `webui/lib/health.js`.

- [ ] **Step 3: 在 `/api/overview` 返回健康摘要，页面把数据链路状态和设备健康状态分开显示；将接口的链路、IP、Zone 合并为单行信息**

- [ ] **Step 4: 运行单测并以 390px 宽度验证页面无横向溢出、关键审批按钮可见**

Run: `node --test webui/test/health.test.js`

Expected: tests pass; no horizontal overflow in the browser check.

### Task 5: 完成回归、文档与发布前检查

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `docs/DEPLOY.md`
- Test: `webui/test/*.test.js`
- Test: `mcp/panos-mcp/tests/**/*.test.ts`

- [ ] **Step 1: 添加内部试用安全模型说明**

Document that API authentication is required, idle timeout intentionally remains disabled for internal testing, state transitions are server-side, and task cleanup does not delete audit events.

- [ ] **Step 2: 运行 WebUI 单元测试**

Run: `node --test webui/test/*.test.js`

Expected: all tests pass.

- [ ] **Step 3: 运行 MCP 既有测试与构建**

Run: `npm --prefix mcp/panos-mcp test && npm --prefix mcp/panos-mcp run build`

Expected: test suite and TypeScript build pass.

- [ ] **Step 4: 在不提交真实任务的情况下进行本地 HTTP 和浏览器冒烟检查**

Run: `curl -sS -o /dev/null -w '%{http_code}' http://localhost:8080/api/overview`

Expected: unauthenticated access returns `401`; authenticated manual checks cover dashboard rendering, task approval visibility and mobile layout.
