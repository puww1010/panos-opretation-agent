'use strict';

const { scalar, toNumber, fields, field, entries, finding, unknown } = require('./helpers');
const text = value => String(scalar(value) ?? '').trim();
const pick = (data, keys) => text(field(data, keys));
const lower = (data, keys) => pick(data, keys).toLowerCase();
const name = entry => text(entry['@_name']) || pick(entry, ['name', 'feature', 'ifname', 'certificate', 'description']) || '未命名';
const threshold = (value, warning, critical) => value >= critical ? 'critical' : value >= warning ? 'warning' : 'ok';
function percent(metric, raw, plane, warning, critical, window) {
  const value = toNumber(raw);
  const extra = { plane, ...(window ? { window } : {}) };
  if (value === null || value < 0 || value > 100) return unknown(metric, extra);
  const severity = threshold(value, warning, critical);
  return finding(metric, value, '%', severity, `${plane} ${metric} 使用率 ${value}%`, severity === 'ok' ? '' : '核对持续负载与容量，排查异常进程或流量', extra);
}
function stateFinding(metric, state, good, bad, severity = 'critical') {
  if (good.includes(state)) return finding(metric, state, '', 'ok', `${metric}：${state}`);
  if (bad.includes(state)) return finding(metric, state, '', severity, `${metric}：${state}`, '检查对应组件状态及事件日志');
  return unknown(metric);
}

function system(data) {
  const source = data.system;
  const result = [stateFinding('operational-mode', lower(source, ['operational-mode']), ['normal'], ['maintenance', 'recovery', 'logger', 'log-collector', 'fips', 'cc'], 'warning')];
  const uptime = pick(source, ['uptime']);
  const days = uptime.match(/^(\d+)\s+days?\b/i);
  if (days) result.push(finding('uptime', uptime, '', Number(days[1]) === 0 ? 'warning' : 'ok', Number(days[1]) === 0 ? '设备在最近一天内重启' : `设备运行时间：${uptime}`, Number(days[1]) === 0 ? '核对计划维护和重启日志' : ''));
  else result.push(unknown('uptime'));
  const version = pick(source, ['sw-version']);
  if (version) result.push(finding('PAN-OS version', version, '', 'info', `PAN-OS 版本：${version}`));
  return result;
}

function environmentals(data) {
  const result = [];
  for (const key of ['power-supply', 'power-supplies', 'fan', 'fans', 'thermal', 'temperature']) {
    for (const group of fields(data.environmentals, [key])) for (const entry of entries(group)) {
      const metric = `${key} ${name(entry)}`;
      const status = lower(entry, ['status']);
      const alarm = lower(entry, ['alarm']);
      if (['true', 'yes', '1'].includes(alarm)) result.push(finding(metric, alarm, '', 'critical', `${metric} 传感器告警`, '检查硬件、散热与供电'));
      else if (status) result.push(stateFinding(metric, status, ['ok', 'up', 'active', 'normal'], ['failed', 'fail', 'down', 'fault', 'bad', 'critical', 'alarm', 'not installed']));
      else if (['false', 'no', '0'].includes(alarm)) result.push(finding(metric, alarm, '', 'ok', `${metric} 无传感器告警`));
      else result.push(unknown(metric));
    }
  }
  return result.length ? result : [unknown('environmentals')];
}

function resources(data) {
  const result = [];
  for (const window of ['second', 'minute', 'hour']) {
    for (const sample of fields(data.resources, [window])) {
      for (const value of fields(sample, ['cpu-load-average'])) {
        const cores = entries(value);
        const samples = cores.flatMap(core => text(core.value).split(',').map(toNumber));
        const average = samples.length && samples.every(v => v !== null && v >= 0 && v <= 100) ? Math.round(samples.reduce((a, b) => a + b, 0) / samples.length * 100) / 100 : null;
        const resultItem = percent('cpu', cores.length ? average : value, 'DP', 80, 95, window);
        if (cores.length && average !== null) resultItem.message += '（各核心、该窗口全部采样点的均值）';
        result.push(resultItem);
      }
    }
  }
  if (!result.length) result.push(unknown('cpu', { plane: 'DP' }));
  const memory = field(data.resources, ['memory']);
  result.push(percent('memory', field(memory, ['percent', 'utilization']), 'DP', 80, 90));
  const mp = data.management_resources;
  let cpu = field(mp, ['cpu-percent', 'cpu-utilization']);
  let mem = field(mp, ['memory-percent']);
  if (typeof mp === 'string') {
    const cpuLine = mp.match(/%?Cpu\(s\)\s*:[^\n]*/i)?.[0];
    const cpuPart = key => cpuLine?.match(new RegExp('([\\d.]+)\\s*%?\\s*' + key + '\\b', 'i'))?.[1];
    if (cpuPart('us') !== undefined && cpuPart('sy') !== undefined) cpu = Number(cpuPart('us')) + Number(cpuPart('sy')) + Number(cpuPart('ni') || 0);
    const memoryLine = mp.match(/(?:KiB|MiB|GiB)?\s*Mem\s*:[^\n]*/i)?.[0];
    const total = memoryLine?.match(/([\d.]+)\s*([kmg]?)\s*total/i);
    const used = memoryLine?.match(/([\d.]+)\s*([kmg]?)\s*used/i);
    if (total && used && total[2].toLowerCase() === used[2].toLowerCase() && Number(total[1]) > 0) mem = Number(used[1]) / Number(total[1]) * 100;
  }
  result.push(percent('cpu', cpu, 'MP', 80, 95, 'OS 估算 us+sy+ni，单次采样；非 WebUI 同期控制面均值'));
  result.push(percent('memory', mem, 'MP', 80, 90));
  return result;
}

function sessions(data) {
  const active = toNumber(field(data.sessions, ['num-active', 'active']));
  const capacity = toNumber(field(data.sessions, ['num-max', 'max']));
  const result = [];
  if (active !== null && active >= 0 && capacity !== null && capacity > 0) {
    const pct = Math.round(active / capacity * 1000) / 10;
    result.push(finding('session-utilization', pct, '%', threshold(pct, 80, 95), `${active} 个活动会话 / 容量 ${capacity}`, pct >= 80 ? '排查突增会话和容量压力' : ''));
  } else result.push(unknown('session-utilization'));
  for (const [key, unit] of [['cps', 'sessions/s'], ['kbps', 'Kbps']]) {
    const value = toNumber(field(data.sessions, [key]));
    if (value !== null && value >= 0) result.push(finding(key, value, unit, 'info', `${key}：${value} ${unit}`));
  }
  return result;
}

function interfaces(data) {
  const result = entries(data.interfaces?.hw || data.interfaces).filter(entry => name(entry) !== '未命名' || field(entry, ['state', 'link-state']) !== undefined).map(entry => {
    const metric = `interface ${name(entry)}`;
    const state = lower(entry, ['state', 'link-state']);
    const admin = lower(entry, ['admin-state', 'admin', 'admin-status']);
    if (['down', 'inactive', 'not-connected'].includes(state) && !['up', 'enabled', 'yes'].includes(admin)) return finding(metric, state, '', 'info', '端口链路未连接，缺少管理员启用证据或端口已关闭', '按端口用途核对预期状态');
    return stateFinding(metric, state, ['up', 'active'], ['down', 'inactive', 'not-connected']);
  });
  return result.length ? result : [unknown('interfaces')];
}

function ha(data) {
  const source = data.ha;
  if (['no', 'false', 'disabled'].includes(lower(source, ['enabled']))) return [finding('ha', false, '', 'info', 'HA 已明确关闭', '', { applicability: 'not_applicable' })];
  return ['local', 'peer'].map(side => stateFinding(`ha-${side}`, lower(field(source, [side, `${side}-info`]), ['state']), ['active', 'passive', 'active-primary', 'active-secondary', 'passive-primary'], ['down', 'not-connected', 'suspended', 'non-functional', 'initial']));
}

function expiryTimestamp(expiry) {
  // Validate calendar components before Date.parse can roll February 30 into March.
  const numeric = expiry.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:$|[T\s])/);
  const named = expiry.match(/^([A-Za-z]{3,9})\s+(\d{1,2})(?:,)?\s+(?:\d{2}:\d{2}:\d{2}\s+)?(\d{4})(?:$|\s)/);
  const months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  if (!numeric && !named) return NaN;
  const year = Number(numeric ? numeric[1] : named[3]);
  const month = numeric ? Number(numeric[2]) : months.indexOf(named[1].slice(0, 3).toLowerCase()) + 1;
  const day = Number(numeric ? numeric[3] : named[2]);
  const calendar = new Date(Date.UTC(year, month - 1, day));
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) return NaN;
  return Date.parse(expiry);
}

function expiryChecks(id, data, context) {
  const now = new Date(context.now ?? Date.now()).getTime();
  const result = entries(data[id]).map(entry => {
    const metric = `${id} ${name(entry)}`;
    const status = lower(entry, ['status']);
    if (['expired', 'not-licensed', 'revoked', 'invalid'].includes(status)) return finding(metric, status, '', 'critical', `${metric}：${status}`, '更新许可证或证书');
    const expiry = pick(entry, id === 'license' ? ['expires', 'expiration-date'] : ['not-valid-after', 'expiry', 'validity-end']);
    if (id === 'license' && /^(never|permanent|never expires)$/i.test(expiry)) return finding(metric, expiry, '', 'ok', `${metric} 为永久许可`);
    const timestamp = expiryTimestamp(expiry);
    if (!Number.isFinite(timestamp) || !Number.isFinite(now)) return unknown(metric);
    const days = Math.floor((timestamp - now) / 86400000);
    const severity = timestamp <= now ? 'critical' : days < 30 ? 'warning' : 'ok';
    return finding(metric, days, 'days', severity, `${metric} 到期日期 ${expiry}，剩余 ${days} 天`, severity === 'ok' ? '' : '安排续订或更新并核对设备时间');
  });
  return result.length ? result : [unknown(id)];
}

const basicChecks = [
  ['system', 'device_health', '系统信息', ['system'], system],
  ['environmentals', 'device_health', '硬件环境', ['environmentals'], environmentals],
  ['resources', 'resource_performance', 'CPU 与内存', ['resources', 'management_resources'], resources],
  ['sessions', 'resource_performance', '会话容量', ['sessions'], sessions],
  ['interfaces', 'network_connectivity', '接口状态', ['interfaces'], interfaces],
  ['ha', 'high_availability', '高可用状态', ['ha'], ha],
  ['license', 'license_subscription', '许可订阅', ['license'], (data, context) => expiryChecks('license', data, context)],
  ['certificates', 'device_health', '证书到期', ['certificates'], (data, context) => expiryChecks('certificates', data, context)]
].map(([id, category, label, sources, evaluate]) => ({ id, category, label, sources, evaluate: (data = {}, context = {}) => evaluate(data, context) }));

module.exports = { basicChecks };
