const test = require("node:test");
const assert = require("node:assert/strict");

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
