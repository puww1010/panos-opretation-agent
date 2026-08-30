function createDashboardService({
  callTool,
  directOp,
  xmlEntries,
  healthSummary,
  topologyNames = () => ({ devices: {}, extra_nodes: {} }),
  firewallHost = "",
  clock = Date.now,
  overviewTtlMs = 5000,
  topologyTtlMs = 20000,
  platformTtlMs = 30000,
  maxMetrics = 720,
} = {}) {
  let overviewCache = null, overviewTs = 0;
  let topologyCache = null, topologyTs = 0;
  let platformCache = null, platformCacheTs = 0;
  const platformBuf = { mp: [], dp: [] };
  const metrics = [];
  const history = [];

  async function getActiveSessions() {
    const xmlAll = await directOp("<show><session><all></all></session></show>");
    const numActive = (xmlAll.match(/<entry>/g) || []).length;
    const xmlInfo = await directOp("<show><session><info></info></session></show>");
    const fields = {};
    const re = /<(\w+)>([^<]+)<\/\1>/g;
    let match;
    while ((match = re.exec(xmlInfo)) !== null) if (!(match[1] in fields)) fields[match[1]] = match[2];
    return { num_active: numActive, num_max: 65536, kbps: fields.kbps, pps: fields.pps, cps: fields.cps };
  }

  function parseInterfaces(raw) {
    const entries = raw?.hw && Array.isArray(raw.hw.entry) ? raw.hw.entry
      : Array.isArray(raw?.entry) ? raw.entry : Array.isArray(raw) ? raw : [];
    return entries.map((item) => ({
      name: item.name || item["@_name"] || "",
      state: String(item.state || item["admin-status"] || item.link || "").toLowerCase(),
      speed: item.speed || item["link-speed"] || "",
      mac: item.mac || item["mac-address"] || "",
      ip: item.ip || item["ip-address"] || "",
      role: item["logical-interface"]?.name || item.type || item.zone || "",
    })).filter((item) => item.name);
  }

  function parseMgmtPlane(text) {
    const out = { name: "Management Plane", status: "offline" };
    if (!text || !text.includes("<result>")) return out;
    out.status = "online";
    const load = text.match(/load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)/);
    if (load) [out.load1, out.load5, out.load15] = load.slice(1).map(Number);
    const cpu = text.match(/%Cpu\(s\):([\s\S]*?)(?=MiB Mem|$)/)?.[1] || "";
    const user = Number(cpu.match(/([\d.]+)\s+us/)?.[1]);
    if (!Number.isNaN(user)) {
      const system = Number(cpu.match(/([\d.]+)\s+sy\b/)?.[1] || 0);
      const nice = Number(cpu.match(/([\d.]+)\s+ni\b/)?.[1] || 0);
      out.cpuUserPct = Math.round(user * 10) / 10;
      out.cpuSysPct = Math.round(system * 10) / 10;
      out.usagePct = Math.max(0, Math.min(100, Math.round((user + system + nice) * 10) / 10));
    }
    const memory = text.match(/MiB Mem\s*:\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used/);
    if (memory) { out.memTotalMB = Math.round(Number(memory[1])); out.memUsedMB = Math.round(Number(memory[3])); }
    return out;
  }

  function parseDataPlane(text) {
    const out = { name: "Data Plane", status: "offline" };
    if (!text || !text.includes("<resource-monitor>")) return out;
    out.status = "online";
    out.processors = (text.match(/<dp\d+>/g) || []).length;
    const second = [...text.matchAll(/<second>([\s\S]*?)<\/second>/g)][0]?.[1] || "";
    const block = second.match(/<cpu-load-average>([\s\S]*?)<\/cpu-load-average>/)?.[1] || "";
    const cores = [...block.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map((match) => match[1]).map((entry) => {
      const samples = (entry.match(/<value>([\s\S]*?)<\/value>/)?.[1] || "").split(",").map(Number).filter(Number.isFinite);
      return samples.length ? samples : null;
    }).filter(Boolean);
    if (cores.length) {
      out.cores = cores.length;
      const averages = cores.map((samples) => samples.reduce((sum, value) => sum + value, 0) / samples.length);
      out.cpuPct = Math.round(averages.reduce((sum, value) => sum + value, 0) / averages.length * 10) / 10;
      out.cpuPeakPct = Math.round(Math.max(...cores.flat()) * 10) / 10;
      const recent = cores.map((samples) => samples.slice(-5).reduce((sum, value) => sum + value, 0) / Math.min(5, samples.length));
      out.cpu5sPct = Math.round(recent.reduce((sum, value) => sum + value, 0) / recent.length * 10) / 10;
    }
    const utilization = second.match(/<resource-utilization>([\s\S]*?)<\/resource-utilization>/)?.[1] || "";
    for (const match of utilization.matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
      const name = match[1].match(/<name>([^<]+)<\/name>/)?.[1];
      const samples = (match[1].match(/<value>([\s\S]*?)<\/value>/)?.[1] || "").split(",").map(Number).filter(Number.isFinite);
      if (!name || !samples.length) continue;
      const average = Math.round(samples.reduce((sum, value) => sum + value, 0) / samples.length * 10) / 10;
      if (/packet buffer/.test(name)) out.pktBufPct = average;
      else if (/^session$/.test(name)) out.sessionUtilPct = average;
      else if (/packet descriptor/.test(name)) out.pktDescPct = average;
    }
    return out;
  }

  function average(samples, key, scale = 100) {
    const values = samples.filter((sample) => sample[key] != null).map((sample) => sample[key]);
    return values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length * scale) / scale : null;
  }

  function smoothMgmt(samples, last) {
    if (!last || last.status !== "online") return { name: "Management Plane", status: "offline", sampleN: 0 };
    if (!samples.length) return { name: "Management Plane", status: "online", sampleN: 0, usagePct: null, load1: null, load5: null, load15: null };
    const load5 = average(samples, "load5");
    const usagePct = average(samples, "usagePct") ?? (load5 == null ? null : Math.max(0, Math.min(100, Math.round(load5 / 4 * 1000) / 10)));
    return { name: last.name || "Management Plane", status: "online", load1: average(samples, "load1"), load5, load15: average(samples, "load15"), cpuUserPct: average(samples, "cpuUserPct"), cpuSysPct: average(samples, "cpuSysPct"), usagePct, usageMethod: average(samples, "usagePct") == null ? "load5/cores" : "us+sy+ni", memUsedMB: last.memUsedMB, memTotalMB: last.memTotalMB, sampleN: samples.length };
  }

  function smoothData(samples, last) {
    if (!last || last.status !== "online") return { name: "Data Plane", status: "offline", sampleN: 0 };
    if (!samples.length) return { name: "Data Plane", status: "online", sampleN: 0, cpuPct: null, cores: null };
    return { name: last.name || "Data Plane", status: "online", processors: last.processors, cores: last.cores, cpuPct: average(samples, "cpuPct", 10), cpuPeakPct: average(samples, "cpuPeakPct", 10), cpu5sPct: average(samples, "cpu5sPct", 10), pktBufPct: average(samples, "pktBufPct", 10), sessionUtilPct: average(samples, "sessionUtilPct", 10), pktDescPct: average(samples, "pktDescPct", 10), sampleN: samples.length };
  }

  async function getPlatformLoading() {
    if (platformCache && clock() - platformCacheTs < platformTtlMs) return platformCache;
    const [mp, dp] = await Promise.allSettled([directOp("<show><system><resources></resources></system></show>"), directOp("<show><running><resource-monitor></resource-monitor></running></show>")]);
    const management = parseMgmtPlane(mp.status === "fulfilled" ? String(mp.value || "") : "");
    const data = parseDataPlane(dp.status === "fulfilled" ? String(dp.value || "") : "");
    for (const [key, sample] of [["mp", management], ["dp", data]]) {
      if (sample.status === "online") { platformBuf[key].push(sample); if (platformBuf[key].length > 5) platformBuf[key].shift(); }
      else platformBuf[key].length = 0;
    }
    platformCache = { managementPlane: smoothMgmt(platformBuf.mp, management), dataPlane: smoothData(platformBuf.dp, data) };
    platformCacheTs = clock();
    return platformCache;
  }

  async function getOverview() {
    if (overviewCache && clock() - overviewTs < overviewTtlMs) return overviewCache;
    const kpi = { device: {}, ha: {}, session: {}, resource: {}, license: {} };
    const values = await Promise.allSettled(["get_firewall_info", "get_ha_status", "get_system_resources", "get_licenses", "get_interfaces"].map((name) => callTool(name, {}, null)).concat([getActiveSessions(), getPlatformLoading()]));
    const [fw, ha, resources, licenses, rawInterfaces, sessions, platform] = values.map((value) => value.status === "fulfilled" ? value.value : null);
    if (fw) kpi.device = { hostname: fw.hostname, model: fw.model, sw: fw["sw-version"], uptime: fw.uptime, serial: fw.serial };
    if (ha) kpi.ha = { enabled: ha.enabled === "yes" || ha.enabled === true };
    if (sessions) kpi.session = { active: sessions.num_active, max: sessions.num_max, kbps: sessions.kbps, pps: sessions.pps };
    if (resources) kpi.resource = { load: resources["load average"], memUsed: resources["mem used"], memTotal: resources["mem total"] };
    if (licenses) { const entries = licenses.entry || []; kpi.license = { total: entries.length, expired: entries.filter((entry) => String(entry.expired).toLowerCase() === "yes").length }; }
    const interfaces = parseInterfaces(rawInterfaces);
    const health = healthSummary({ kpi, interfaces, platform: platform || null });
    overviewCache = { ts: clock(), kpi, interfaces, platform: platform || null, health };
    overviewTs = clock();
    metrics.push({ ts: overviewCache.ts, kpi: JSON.parse(JSON.stringify(kpi)), health: health.level });
    if (metrics.length > maxMetrics) metrics.shift();
    return overviewCache;
  }

  async function getTopology() {
    if (topologyCache && clock() - topologyTs < topologyTtlMs) return topologyCache;
    const names = topologyNames();
    const values = await Promise.allSettled(["get_firewall_info", "get_interfaces", "get_zones"].map((name) => callTool(name, {}, null)));
    const [fw, rawInterfaces, rawZones] = values.map((value) => value.status === "fulfilled" ? value.value : null);
    const readEntries = async (command) => { try { return xmlEntries(await directOp(command)); } catch { return []; } };
    const [routes, arp] = await Promise.all([readEntries("<show><routing><route></route></routing></show>"), readEntries("<show><arp><entry name='all'/></arp></show>")]);
    const fwNode = { type: "firewall", ip: firewallHost || fw?.["ip-address"] || "", name: "PA-440 防火墙", hostname: fw?.hostname || "", model: fw?.model || "", swVersion: fw?.["sw-version"] || "", serial: fw?.serial || "" };
    const zones = rawZones?.zone?.entry || rawZones?.entry || [];
    const zoneByInterface = {};
    for (const zone of zones) for (const members of [zone.network?.layer2?.member, zone.network?.layer3?.member, zone.network?.["virtual-wire"]?.member]) for (const member of members == null ? [] : Array.isArray(members) ? members : [members]) zoneByInterface[member] = zone["@_name"];
    const interfaces = parseInterfaces(rawInterfaces).map((item) => ({ type: "interface", ...item, zone: zoneByInterface[item.name] || item.role || "" }));
    const gateways = [...new Map(routes.map((route) => [route.nexthop || route["ip-address"], route]).filter(([ip]) => ip && ip !== "0.0.0.0").map(([ip, route]) => [ip, { ip, isInternet: String(route.destination || "").includes("0.0.0.0"), viaIf: route.interface || "", dest: route.destination || "" }])).values()];
    const devices = new Map();
    for (const entry of arp) {
      const ip = entry.ip || entry["ip-address"] || "";
      if (!ip || devices.has(ip)) continue;
      const config = names.devices?.[ip] || {};
      devices.set(ip, { ip, mac: entry.mac || entry["mac-address"] || "", iface: entry.interface || entry.ifname || "", name: config.name || ip, icon: config.icon || "pc" });
    }
    for (const [ip, config] of Object.entries(names.extra_nodes || {})) if (!devices.has(ip)) devices.set(ip, { ip, mac: config.mac || "", iface: config.iface || "", name: config.name || ip, icon: config.icon || "pc" });
    devices.delete(fwNode.ip);
    for (const device of devices.values()) device.agg = ["switch", "router", "ap"].includes(device.icon) ? 1 : 0;
    topologyCache = { ts: clock(), fw: fwNode, interfaces, gateways, devices: [...devices.values()], hasDefault: gateways.some((gateway) => gateway.isInternet), ok: Boolean(fwNode.hostname || fwNode.ip) };
    topologyTs = clock();
    return topologyCache;
  }

  function getMetrics(minutes = 120) {
    const windowMinutes = Math.max(1, Math.min(1440, Number(minutes) || 120));
    const series = metrics.filter((metric) => metric.ts >= clock() - windowMinutes * 60000);
    return { series, count: series.length, windowMinutes, note: "指标采样缓冲（10s 粒度，滚窗 2h）；切库后由 metrics 表提供" };
  }

  function recordHistory(entry) { history.unshift({ ts: new Date(clock()).toLocaleString("zh-CN"), ...entry }); if (history.length > 20) history.pop(); }

  return { getMetrics, getOverview, getTopology, recordHistory, getHistory: () => history };
}

module.exports = { createDashboardService };
