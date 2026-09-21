const { sourceError } = require("./sources");

const CATEGORIES = Object.freeze({ device_health: "设备健康", resource_performance: "资源性能", network_connectivity: "网络连通", security_policy: "安全策略", high_availability: "高可用", license_subscription: "许可与订阅", remote_access_vpn: "远程接入与 VPN", sdwan: "SD-WAN" });
const SKILL_REVISION = "09146cd68e394a0795c6296dfde30dea7139be0b";
const SEVERITIES = ["unknown", "info", "ok", "warning", "critical"];

function sanitize(value, depth = 0, previewLimit = Infinity) {
  if (depth > 7) return "[内容已截断]";
  if (typeof value === "string") return value.replace(/([?&](?:key|api_key|token|password|user)=)[^&\s<>"']*/gi, "$1***")
    .replace(/(<(?:key|password|token|secret)>)[\s\S]*?(<\/[^>]+>)/gi, "$1***$2")
    .replace(/\b(?:Bearer|Basic)\s+[^\s"<>]+/gi, "***")
    .replace(/\b[A-Za-z0-9+/=_-]{48,}\b/g, "***").slice(0, 2000);
  if (Array.isArray(value)) return value.slice(0, previewLimit).map((item) => sanitize(item, depth + 1, previewLimit));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).slice(0, previewLimit).map(([key, item]) => [key, /password|passwd|passphrase|token|api.?key|private.?key|secret|cookie|authorization|authcode|community|(?:^|_)key$/i.test(key) ? "***" : sanitize(item, depth + 1, previewLimit)]));
  return value;
}

function evidencePreview(data) {
  const safe = sanitize(data, 0, 50);
  const text = JSON.stringify(safe);
  return text && text.length > 4000 ? { preview: text.slice(0, 4000), truncated: true } : safe;
}

function worstSeverity(findings) {
  return findings.reduce((worst, finding) => SEVERITIES.indexOf(finding.severity) > SEVERITIES.indexOf(worst) ? finding.severity : worst, "unknown");
}

function createMonitorService({ readSource, clock = Date.now, definitions, sourceTimeoutMs = 30000, totalTimeoutMs = 600000 } = {}) {
  const checks = definitions || [...require("./basic-checks").basicChecks, ...require("./device-checks").deviceChecks, ...require("./network-checks").networkChecks, ...require("./security-checks").securityChecks];
  const listChecks = () => checks.map(({ id, category, label }) => ({ id, category, categoryLabel: CATEGORIES[category], label }));

  async function run({ firewall, checks: ids, category, minutes = 10, signal, onProgress = () => {} } = {}) {
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) throw new Error("时间窗口必须为 1–60 分钟");
    if (ids && (!Array.isArray(ids) || !ids.length || ids.some((id) => !checks.some((check) => check.id === id)))) throw new Error("未知检查项");
    if (category && !Object.hasOwn(CATEGORIES, category)) throw new Error("未知检查分类");
    const selected = checks.filter((check) => (!ids || ids.includes(check.id)) && (!category || check.category === category));
    if (!selected.length) throw new Error("没有可执行的检查项");
    const started = clock();
    const stop = new AbortController();
    const timeout = setTimeout(() => stop.abort(Object.assign(new Error("巡检超时"), { code: "timeout" })), totalTimeoutMs);
    const runSignal = signal ? AbortSignal.any([signal, stop.signal]) : stop.signal;
    const cache = new Map();
    const report = { schemaVersion: 1, skillId: "panos-monitor", skillRevision: SKILL_REVISION, firewall, minutes, startedAt: new Date(started).toISOString(), executionStatus: "running", overallSeverity: "unknown", checks: [], coverage: { total: selected.length, valid: 0, partial: 0, error: 0, unsupported: 0, not_applicable: 0, unknown: 0, not_run: selected.length } };

    async function read(source) {
      if (cache.has(source)) return cache.get(source);
      const controller = new AbortController();
      const linked = AbortSignal.any([runSignal, controller.signal]);
      let timer, abort;
      const pending = (async () => {
        try {
          const data = await Promise.race([
            Promise.resolve().then(() => { linked.throwIfAborted(); return readSource(source, firewall, { signal: linked, minutes }); }),
            new Promise((_, reject) => {
              abort = () => reject(linked.reason);
              linked.addEventListener("abort", abort, { once: true });
              timer = setTimeout(() => controller.abort(Object.assign(new Error("采集超时"), { code: "timeout" })), sourceTimeoutMs);
            }),
          ]);
          linked.throwIfAborted();
          return { data, source, observedAt: new Date(clock()).toISOString() };
        } catch (error) { return { source, error: sourceError(error) }; }
        finally { clearTimeout(timer); linked.removeEventListener("abort", abort); }
      })();
      cache.set(source, pending);
      return pending;
    }

    try {
      for (const definition of selected) {
        if (runSignal.aborted) break;
        const checkStarted = clock();
        await onProgress({ id: definition.id, label: definition.label, status: "running", completed: report.checks.length, total: selected.length });
        const data = {}, sources = [], errors = [];
        for (const source of definition.sources) {
          if (runSignal.aborted) break;
          const result = await read(source);
          if (result.error) { errors.push(result.error); sources.push({ id: source, status: "error", errorCode: result.error.code, message: result.error.message }); }
          else { data[source] = result.data; sources.push({ id: source, status: "ok", observedAt: result.observedAt }); }
          if (definition.id === "ha_diagnostics" && source === "ha_all" && ["no", "false", "disabled"].includes(String(result.data?.enabled).toLowerCase())) break;
        }
        if (runSignal.aborted) break;
        let findings;
        try { findings = definition.evaluate(data, { now: clock(), minutes }); }
        catch { findings = [{ metric: "解析", severity: "unknown", message: "响应结构无法识别，未作健康判断", recommendation: "核对该型号与版本的响应格式" }]; }
        if (!Array.isArray(findings) || !findings.length) findings = [{ metric: "证据", severity: "unknown", message: "未获得可判断的监控证据", recommendation: "检查功能配置与采集兼容性" }];
        const valid = findings.some((finding) => ["ok", "info", "warning", "critical"].includes(finding.severity));
        const notApplicable = findings.every((finding) => finding.applicability === "not_applicable");
        const unknown = findings.some((finding) => finding.severity === "unknown");
        const collection = errors.length === definition.sources.length ? (errors.every((error) => error.code === "unsupported") ? "unsupported" : "error")
          : errors.length ? "partial" : notApplicable ? "not_applicable" : !valid ? "unknown" : unknown ? "partial" : "ok";
        for (const error of errors) findings.push({ metric: "采集", severity: "unknown", message: error.message, recommendation: "检查设备连接、权限或命令兼容性" });
        const item = sanitize({ id: definition.id, label: definition.label, category: definition.category, categoryLabel: CATEGORIES[definition.category], collection, severity: worstSeverity(findings), findings, sources, observedAt: new Date(clock()).toISOString(), durationMs: clock() - checkStarted, evidence: Object.fromEntries(Object.entries(data).map(([key, value]) => [key, evidencePreview(value)])) });
        report.checks.push(item);
        report.coverage[collection === "ok" ? "valid" : collection] += 1;
        report.coverage.not_run -= 1;
        await onProgress({ id: definition.id, label: definition.label, status: collection === "error" ? "err" : "ok", completed: report.checks.length, total: selected.length, check: item });
      }
    } finally { clearTimeout(timeout); }
    report.finishedAt = new Date(clock()).toISOString();
    report.durationMs = clock() - started;
    report.overallSeverity = worstSeverity(report.checks.flatMap((check) => check.findings));
    const incomplete = report.coverage.partial + report.coverage.error + report.coverage.unsupported + report.coverage.unknown + report.coverage.not_run;
    report.executionStatus = signal?.aborted ? "cancelled" : stop.signal.aborted ? "partial"
      : report.coverage.error === selected.length ? "failed" : incomplete ? "partial" : "completed";
    if (report.overallSeverity === "ok" && incomplete) report.overallSeverity = "unknown";
    report.coverage.percent = Math.round((report.coverage.valid + report.coverage.not_applicable) / selected.length * 100);
    return report;
  }
  return { run, listChecks };
}

module.exports = { createMonitorService, CATEGORIES, SKILL_REVISION, sanitize };
