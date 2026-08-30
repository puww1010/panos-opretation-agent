const test = require("node:test");
const assert = require("node:assert/strict");

const { createDashboardService } = require("../services/dashboard-service");

test("dashboard service composes overview, caches it, and exposes a bounded metric window", async () => {
  let now = 1_700_000_000_000;
  let calls = 0;
  const service = createDashboardService({
    clock: () => now,
    callTool: async (name) => {
      calls += 1;
      return {
        get_firewall_info: { hostname: "fw-a", model: "PA-440", "sw-version": "11.2", uptime: "3 days", serial: "001" },
        get_ha_status: { enabled: "yes" },
        get_system_resources: { "load average": "1.0, 2.0, 3.0", "mem used": "100 MiB", "mem total": "200 MiB" },
        get_licenses: { entry: [{ expired: "no" }, { expired: "yes" }] },
        get_interfaces: { entry: [{ name: "ethernet1/1", state: "up", ip: "192.0.2.1" }] },
      }[name];
    },
    directOp: async (command) => command.includes("session><all")
      ? "<entry></entry><entry></entry>"
      : command.includes("session><info")
        ? "<kbps>12</kbps><pps>3</pps>"
        : "<result>load average: 1.0, 2.0, 3.0\n%Cpu(s): 5.0 us, 2.0 sy, 0.0 ni\nMiB Mem : 200 total, 100 free, 100 used</result>",
    healthSummary: ({ kpi }) => ({ level: kpi.license.expired ? "attention" : "normal" }),
    overviewTtlMs: 5_000,
  });

  const first = await service.getOverview();
  const second = await service.getOverview();

  assert.equal(first.kpi.device.hostname, "fw-a");
  assert.equal(first.kpi.session.active, 2);
  assert.equal(first.kpi.license.expired, 1);
  assert.equal(first.health.level, "attention");
  assert.equal(second, first);
  assert.equal(calls, 5);
  assert.deepEqual(service.getMetrics(120).series, [{ ts: now, kpi: first.kpi, health: "attention" }]);
});

test("dashboard service builds topology with the injected firewall host instead of a server global", async () => {
  const service = createDashboardService({
    firewallHost: "198.51.100.1",
    callTool: async (name) => ({
      get_firewall_info: { hostname: "fw-a", model: "PA-440" },
      get_interfaces: { entry: [{ name: "ethernet1/1", state: "up", ip: "192.0.2.1" }] },
      get_zones: { zone: { entry: [{ "@_name": "Trust", network: { layer3: { member: "ethernet1/1" } } }] } },
    })[name],
    directOp: async () => "",
    xmlEntries: () => [],
    topologyNames: () => ({ devices: {}, extra_nodes: {} }),
  });

  const topology = await service.getTopology();

  assert.equal(topology.fw.ip, "198.51.100.1");
  assert.equal(topology.interfaces[0].zone, "Trust");
  assert.equal(topology.ok, true);
});
