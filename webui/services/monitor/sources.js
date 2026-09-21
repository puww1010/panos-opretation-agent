// Fixed read-only operations. Never construct XML from a user supplied command.
const SOURCES = Object.freeze({
  system: "<show><system><info/></system></show>",
  environmentals: "<show><system><environmentals/></system></show>",
  resources: "<show><running><resource-monitor/></running></show>",
  management_resources: "<show><system><resources/></system></show>",
  sessions: "<show><session><info/></session></show>",
  interfaces: "<show><interface>all</interface></show>",
  ha: "<show><high-availability><state/></high-availability></show>",
  license: "<request><license><info/></license></request>",
  certificates: null, // Existing config-read tool; public metadata only.
  disk_space: "<show><system><disk-space/></system></show>",
  logdb_quota: "<show><system><logdb-quota/></system></show>",
  software_status: "<show><system><software><status/></software></system></show>",
  global_counters: "<show><counter><global><filter><severity>drop</severity><delta>no</delta></filter></global></counter></show>",
  app_stats: "<show><system><statistics><application/></statistics></system></show>",
  discard_sessions: "<show><session><all><filter><state>discard</state></filter></all></session></show>",
  transceivers: "<show><transceiver-detail>all</transceiver-detail></show>",
  routing: "<show><routing><route/></routing></show>",
  bgp: "<show><routing><protocol><bgp><neighbor/></bgp></protocol></routing></show>",
  ospf: "<show><routing><protocol><ospf><neighbor/></ospf></protocol></routing></show>",
  rule_hits: "<show><rule-hit-count><vsys><vsys-name><entry name=\"vsys1\"><rule-base><entry name=\"security\"><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>",
  zone_protection: "<show><zone-protection/></show>",
  decryption: "<show><decryption/></show>",
  ha_all: "<show><high-availability><all/></high-availability></show>",
  ha_link: "<show><high-availability><link-monitoring/></high-availability></show>",
  ha_path: "<show><high-availability><path-monitoring/></high-availability></show>",
  ha_sync: "<show><high-availability><state-synchronization/></high-availability></show>",
  ha_flaps: "<show><high-availability><flap-statistics/></high-availability></show>",
  jobs: "<show><jobs><all/></jobs></show>",
  edl: "<request><system><external-list><show><type>ip</type></show></external-list></system></request>",
  fqdn: "<show><dns-proxy><fqdn><all/></fqdn></dns-proxy></show>",
  vpn: "<show><vpn><ipsec-sa/></vpn></show>",
  ike: "<show><vpn><ike-sa/></vpn></show>",
  globalprotect: "<show><global-protect-gateway><current-user/></global-protect-gateway></show>",
  dns_proxy: "<show><dns-proxy><statistics><all/></statistics></dns-proxy></show>",
  user_id: "<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>",
  user_groups: "<show><user><group-mapping><state>all</state></group-mapping></user></show>",
  sdwan: "<show><sdwan/></show>",
  path_monitor: "<show><routing><path-monitor/></routing></show>",
  threat_logs: null, // Bounded log query, handled through the existing log tool.
});

const ERROR_MESSAGES = Object.freeze({
  authentication: "认证或权限不足，未获得有效监控数据",
  unsupported: "设备不支持此查询或命令参数，需核对 PAN-OS 版本与功能",
  timeout: "采集超时，未获得有效监控数据",
  connection: "无法连接采集服务或防火墙",
  response: "采集返回错误或无法识别的响应",
  clock: "无法确认设备时间，未查询假定的日志时间窗口",
});

function sourceError(error) {
  const text = String(error?.message || error || "");
  const code = Object.hasOwn(ERROR_MESSAGES, error?.code) ? error.code
    : /403|401|unauthori|invalid.*key|authenti|permission|权限|认证/i.test(text) ? "authentication"
    : /unknown command|unrecognized command|invalid command|invalid client cli|unsupported|not supported|Invalid syntax|unexpected|is invalid|is missing|non NULL|deprecated/i.test(text) ? "unsupported"
    : /timeout|timed out|超时/i.test(text) ? "timeout"
    : /ECONN|ENOTFOUND|connect|fetch failed/i.test(text) ? "connection" : "response";
  return Object.assign(new Error(ERROR_MESSAGES[code]), { code });
}

function validateSourceResult(data) {
  const raw = typeof data === "string" ? data : data?.raw;
  if (data?.success === false || data?.error || data?.entry?.error || (typeof raw === "string" && (/^\s*(?:Error:|<response[^>]+status=["']error)/i.test(raw) || /command.*deprecated/i.test(raw)))) {
    throw sourceError(data?.error || data?.entry?.error || raw);
  }
  return data?.success === true ? data.data : (data && Object.keys(data).length === 1 && typeof data.raw === "string" ? data.raw : data);
}

function deviceLogWindow(time, minutes) {
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) throw new Error("日志时间窗口必须为 1–60 分钟");
  const text = String(time || "").trim();
  let parts = text.match(/^(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/)?.slice(1).map(Number);
  if (!parts) {
    const value = text.match(/^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/);
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    if (value && months.includes(value[1])) parts = [Number(value[6]), months.indexOf(value[1]) + 1, Number(value[2]), Number(value[3]), Number(value[4]), Number(value[5])];
  }
  const [year, month, day, hour, minute, second] = parts || [];
  const end = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (!parts || end.getUTCFullYear() !== year || end.getUTCMonth() !== month - 1 || end.getUTCDate() !== day || end.getUTCHours() !== hour || end.getUTCMinutes() !== minute || end.getUTCSeconds() !== second) throw Object.assign(new Error(ERROR_MESSAGES.clock), { code: "clock" });
  const format = (date) => date.toISOString().slice(0, 19).replace(/-/g, "/").replace("T", " ");
  const startTime = format(new Date(end.getTime() - minutes * 60000)), endTime = format(end);
  return { start: startTime, end: endTime, clock: "device", minutes, query: "(receive_time geq '" + startTime + "') and (receive_time leq '" + endTime + "')" };
}

module.exports = { SOURCES, ERROR_MESSAGES, sourceError, validateSourceResult, deviceLogWindow };
