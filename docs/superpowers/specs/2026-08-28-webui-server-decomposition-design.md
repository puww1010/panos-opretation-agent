# WebUI Server Decomposition Design

## Goal

Resolve the first confirmed architecture issue: `webui/server.js` is a God Module. Split its PAN-OS integration, task orchestration, LLM orchestration, dashboard aggregation, and HTTP routing into focused modules while preserving the existing internal-pilot behavior.

## Fixed Constraints

- Keep every existing `/api/*` response contract, authentication rule, task state, and Feishu bridge behavior unless a test proves an existing defect.
- Keep `IDLE_MINUTES = 0`; internal testing must not add an idle re-login requirement.
- Do not alter or inspect the user-managed runtime files `cfgs/llm-choice.json` and `cfgs/tasks.json`.
- Do not add a database, framework, queue, or new runtime dependency.
- Preserve candidate-before-commit safety, plan fingerprints, task audit persistence, and same-origin API authorization behavior introduced for the internal pilot.
- Use CommonJS and the existing Node.js HTTP server style.
- Validate only with non-production firewall access. The architecture migration itself does not authorize a new configuration write.

## Considered Approaches

### A. Move the entire file to `app.js`

This would make `server.js` short, but would merely rename the God Module. It does not establish testable boundaries and therefore does not resolve the architecture issue.

### B. Extract all logic at once into a framework-based application

This could create clean abstractions, but it changes routing and middleware semantics at the same time as the domain code. It adds unnecessary dependency and regression risk for an internal pilot.

### C. Incremental service extraction behind the current HTTP contract (selected)

Keep the native HTTP server and API paths. Extract one responsibility at a time behind small CommonJS factories, write focused contract tests first, and run the full existing suite after each stage. This minimizes behavioral change while making the first architecture issue objectively complete.

## Target Structure

```text
webui/
  server.js                         process entry: create app, listen, shutdown logging
  app.js                            dependency composition only
  adapters/
    panos-adapter.js                MCP and direct PAN-OS transport operations
  services/
    task-service.js                 task lifecycle, candidate/commit, audit and history
    llm-service.js                  LLM configuration, intent analysis and diagnostics
    dashboard-service.js            overview, topology and metrics aggregation
    auth-service.js                 existing auth/session decisions as a narrow service
  routes/
    api-routes.js                   request parsing, auth dispatch and response mapping
    static-routes.js                static asset handling and root page delivery
  lib/
    security.js                     existing security helpers
    task-governance.js              existing pure task transition rules
    health.js                       existing pure dashboard health rules
```

`app.js` owns construction order and dependency injection. Routes may parse requests and map errors to the existing HTTP response shape, but may not call PAN-OS, formulate LLM prompts, or mutate task state directly. Services may depend on injected collaborators, not on HTTP request objects.

## Five Incremental Stages

### 1. PAN-OS Adapter

Move direct HTTPS functions, MCP client calls, curated operations, and firewall target normalization to `adapters/panos-adapter.js`. Expose a narrow adapter object for read, candidate-change, and commit operations. Existing API output and PAN-OS XML handling remain unchanged.

### 2. Task Service

Move task creation, approval/selection/cancellation transitions, candidate execution, commit execution, task audit records, history, and plan-fingerprint checks to `services/task-service.js`. The service owns the in-memory task collection and persisted audit history; routes only invoke declared task actions.

### 3. LLM Service

Move LLM provider configuration, configuration selection, prompt/context assembly, intent parsing, diagnostic summary generation, and LLM logs to `services/llm-service.js`. It receives the PAN-OS adapter and task service only through explicit methods needed to produce an action plan.

### 4. Dashboard and Route Layer

Move overview/topology/metrics composition to `services/dashboard-service.js`; move existing authentication/session decisions to `services/auth-service.js`; move HTTP endpoint branches to grouped route handlers. Route handlers retain existing status codes and JSON field names.

### 5. Entry Composition and Cleanup

Reduce `server.js` to startup configuration and `app.listen`. Put dependency wiring in `app.js`, remove obsolete in-file implementations and imports introduced solely by the old monolith, and correct the known plan-preview default so a new address-object preview never renders its type as `undefined`.

## Module Interfaces

- `createPanosAdapter(options)` returns direct/MCP read and change operations. It owns transport and no task state.
- `createTaskService({ panosAdapter, transitionTask, auditStore, ... })` returns task queries and lifecycle commands. It owns task mutation and no HTTP handling.
- `createLlmService({ taskService, panosAdapter, configStore, ... })` returns LLM configuration and plan-generation commands. It owns no HTTP handling or PAN-OS transport details.
- `createDashboardService({ panosAdapter, healthSummary, ... })` returns overview, topology, metrics, and history views.
- `createAuthService({ authStore, clock, ... })` returns login/session/change-password operations. Its idle timeout remains disabled by configuration.
- `createApiRouter({ authService, taskService, llmService, dashboardService, ... })` returns the request dispatcher and static responder. It owns status-code and JSON-response mapping only.

## Error Handling and Compatibility

- Preserve existing client-facing Chinese error text and HTTP status where tests cover it.
- Keep PAN-OS/MCP errors structured at the adapter boundary; services may convert them into the current task failure/audit records.
- Do not log credentials, API keys, authorization headers, cookies, or raw LLM configuration values.
- Unknown routes remain handled by the current static/404 behavior.

## Test and Acceptance Strategy

Before production code in each stage, add a focused failing contract test for that module boundary. After each stage run the affected tests and `node --check` on changed JavaScript files. At the end run:

1. `node --test webui/test/*.test.js`.
2. MCP test suite and TypeScript build using the bundled Node 22.22.2 runtime.
3. `git diff --check`.
4. A localhost HTTP smoke test for security headers, unauthenticated API rejection, authenticated overview, task listing, and idle timeout value `0`.
5. A non-production, read-only PAN-OS dashboard/API validation. Do not run a new candidate/commit mutation unless the user separately requests it.

The first architecture issue is complete only when `server.js` contains no direct PAN-OS/MCP call, LLM prompt/config logic, task lifecycle orchestration, or dashboard aggregation; all listed checks pass; and API behavior remains compatible.

## Execution Workspace Decision

The current `main` checkout has required but uncommitted implementation changes alongside user-managed runtime files. A normal linked worktree starts from committed `HEAD` and would omit the required implementation baseline.

Accordingly, do not create a worktree by copying, stashing, or committing those changes implicitly. Before implementation, choose one explicit route:

1. **Work in the existing checkout** and preserve the two user-managed runtime files untouched. This is the recommended route for this already-dirty internal-pilot baseline.
2. **Create a clean baseline commit first**, then create an isolated worktree. This requires the user's explicit authorization for a commit and a decision about which current files belong in it.

No commit is created by this design step.
