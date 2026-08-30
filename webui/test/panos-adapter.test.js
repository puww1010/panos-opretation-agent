const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { createPanosAdapter } = require("../adapters/panos-adapter");

test("adapter selects direct or MCP transport by configured route", async () => {
  const calls = [];
  const adapter = createPanosAdapter({
    toolRoutes: { routes: { get_system_logs: "direct" }, _default: "auto" },
    callMcpTool: async (name) => {
      calls.push(["mcp", name]);
      return { via: "mcp" };
    },
    callDirectTool: async (name) => {
      calls.push(["direct", name]);
      return { via: "direct" };
    },
  });

  assert.deepEqual(await adapter.callTool("get_system_logs", {}), { via: "direct" });
  assert.deepEqual(await adapter.callTool("get_firewall_info", {}), { via: "mcp" });
  assert.deepEqual(calls, [["direct", "get_system_logs"], ["mcp", "get_firewall_info"]]);
});

test("adapter connection does not depend on an implicit global path", () => {
  const script = [
    "delete global.path;",
    "const { createPanosAdapter } = require('./webui/adapters/panos-adapter');",
    "const adapter = createPanosAdapter({ nodeBin: process.execPath, panosMcpDir: '/tmp', sourcePath: '/definitely-missing-panos-mcp-entry.js', workingDirectory: '/tmp' });",
    "adapter.connect().then(() => process.exit(0)).catch((error) => process.exit(String(error.message || error) === 'path is not defined' ? 1 : 0));",
    "setTimeout(() => process.exit(2), 4000);",
  ].join("\n");
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: path.resolve(__dirname, "../.."), encoding: "utf8", timeout: 6000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("adapter exposes only the default firewall display target", () => {
  const adapter = createPanosAdapter({ directFirewall: { name: "lab-fw", host: "198.51.100.1", api_key: "test-secret" } });

  assert.deepEqual(adapter.getDefaultFirewall(), { name: "lab-fw", host: "198.51.100.1" });
});
