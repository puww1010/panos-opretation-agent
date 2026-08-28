const LEVELS = { normal: 0, attention: 1, alert: 2 };

function buildHealthSummary({ kpi = {}, interfaces = [], platform = null }) {
  const items = [];
  const device = kpi.device || {};
  const license = kpi.license || {};
  const ha = kpi.ha || {};

  if (!device.hostname) {
    items.push({ code: "device_data_unavailable", level: "alert", message: "未获取到设备数据" });
  }
  if (Number(license.expired || 0) > 0) {
    items.push({ code: "licenses_expired", level: "alert", message: `${license.expired} 项许可证已过期` });
  }
  for (const item of interfaces.filter((item) => String(item.state || "").toLowerCase() === "down")) {
    items.push({ code: "interface_down", level: "attention", message: `接口 ${item.name} 处于 DOWN 状态` });
  }
  if (ha.enabled === false) {
    items.push({ code: "ha_disabled", level: "attention", message: "HA 未启用" });
  }

  const planes = [
    ["management_plane_load", "Management Plane", platform && platform.managementPlane],
    ["data_plane_load", "Data Plane", platform && platform.dataPlane],
  ];
  for (const [code, name, plane] of planes) {
    const usage = Number(plane && plane.usagePct);
    if (plane && plane.status === "online" && Number.isFinite(usage) && usage >= 60) {
      items.push({ code, level: usage >= 80 ? "alert" : "attention", message: `${name} 使用率 ${usage}%` });
    }
  }

  const level = items.reduce((current, item) => LEVELS[item.level] > LEVELS[current] ? item.level : current, "normal");
  return { level, items };
}

module.exports = { buildHealthSummary };
