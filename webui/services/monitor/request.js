const { CATEGORIES } = require("./service");
const BASIC = ["system", "environmentals", "resources", "sessions", "interfaces", "ha", "license", "certificates"];
const LABELS = { system: "系统信息", environmentals: "硬件环境", resources: "资源性能", sessions: "会话", interfaces: "接口", ha: "HA", license: "许可证", certificates: "证书", disk_space: "磁盘", logdb_quota: "日志配额", software_status: "进程", global_counters: "全局丢包", app_stats: "应用统计", discard_sessions: "丢弃会话", transceivers: "光模块", routing: "路由", rule_hits: "规则命中", zone_protection: "区域防护", decryption: "解密", threat_logs: "威胁日志", ha_diagnostics: "HA深度诊断", jobs: "作业", edl: "EDL", fqdn: "FQDN", vpn: "VPN", globalprotect: "GlobalProtect", dns_proxy: "DNS代理", user_id: "User-ID", sdwan: "SD-WAN" };
const invalid = message => Object.assign(new Error(message), { code: "MONITOR_INPUT" });

function parseMonitorRequest(input) {
  const text = String(input || "").trim().replace(/[。！!？?]+$/, "");
  const match = text.match(/^(?:请)?(?:执行|运行|开始)?\s*(?:深度健康巡检|深度巡检|panos-monitor|monitor)(?:\s*[:：]?\s*(.*))?$/i);
  const short = text.match(/^(?:请)?检查(证书|HA|许可证|磁盘|光模块|SD-WAN)$/i);
  if (!match && !short) return null;
  let scope = (match ? match[1] : short[1]) || "全部";
  const time = scope.match(/(?:最近)?\s*(\d+)\s*分钟/);
  const minutes = time ? Number(time[1]) : 10;
  if (minutes < 1 || minutes > 60) throw invalid("深度巡检时间窗口必须为 1–60 分钟");
  if (time) scope = scope.replace(time[0], "").trim();
  if (!scope || /^(全部|全量|all)$/i.test(scope)) return { minutes };
  if (/^(基础|基础八项|basic)$/i.test(scope)) return { minutes, checks: BASIC };
  const category = Object.keys(CATEGORIES).find((key) => key.toLowerCase() === scope.toLowerCase() || CATEGORIES[key] === scope);
  if (category) return { minutes, category };
  const selected = scope.split(/[、,，]/).map((value) => value.trim());
  const checks = selected.map((value) => Object.keys(LABELS).find((key) => key.toLowerCase() === value.toLowerCase() || LABELS[key].toLowerCase() === value.toLowerCase()));
  if (checks.some((id) => !id)) throw invalid("未知深度巡检范围，请使用分类或检查项名称");
  return { minutes, checks: [...new Set(checks)] };
}

module.exports = { parseMonitorRequest };
