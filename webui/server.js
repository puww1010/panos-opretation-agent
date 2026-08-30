#!/usr/bin/env node
// PAN-OS 防火墙 Agent 控制台进程入口。
const { createApplication } = require("./app");

const application = createApplication();
application.server.listen(application.port, async () => {
  console.log(`[agent] PAN-OS Agent 控制台: http://localhost:${application.port}`);
  try { await application.connect(); } catch (error) { console.error("[agent] MCP connect fail:", error.message); }
});
