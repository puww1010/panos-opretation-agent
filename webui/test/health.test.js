const test = require("node:test");
const assert = require("node:assert/strict");

const { buildHealthSummary } = require("../lib/health");

test("expired licenses and down interfaces prevent an otherwise reachable device from being normal", () => {
  const summary = buildHealthSummary({
    kpi: { device: { hostname: "pa-440" }, license: { expired: 3 }, ha: { enabled: false } },
    interfaces: [{ name: "ethernet1/5", state: "down" }],
    platform: null,
  });

  assert.equal(summary.level, "alert");
  assert.deepEqual(summary.items.map((item) => item.code), ["licenses_expired", "interface_down", "ha_disabled"]);
});

test("high management-plane utilization is surfaced as attention", () => {
  const summary = buildHealthSummary({
    kpi: { device: { hostname: "pa-440" }, license: { expired: 0 }, ha: { enabled: true } },
    interfaces: [{ name: "ethernet1/3", state: "up" }],
    platform: { managementPlane: { status: "online", usagePct: 67 }, dataPlane: { status: "online", usagePct: 12 } },
  });

  assert.equal(summary.level, "attention");
  assert.deepEqual(summary.items.map((item) => item.code), ["management_plane_load"]);
});

test("missing device data is an alert even when no other indicators are available", () => {
  const summary = buildHealthSummary({ kpi: {}, interfaces: [], platform: null });

  assert.equal(summary.level, "alert");
  assert.deepEqual(summary.items.map((item) => item.code), ["device_data_unavailable"]);
});
