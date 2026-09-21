'use strict';

function scalar(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return scalar(value['#text']);
  return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' ? value : undefined;
}

function toNumber(value) {
  value = scalar(value);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string' || !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim())) return null;
  const number = Number(value.trim());
  return Number.isFinite(number) ? number : null;
}

// Parsed command trees only; bound both nesting and total work.
function fields(root, keys) {
  const names = new Set(Array.isArray(keys) ? keys : [keys]);
  const found = [];
  const seen = new Set();
  let visited = 0;
  function visit(value, depth) {
    if (!value || typeof value !== 'object' || depth > 12 || visited++ >= 10000 || seen.has(value)) return;
    seen.add(value);
    for (const [key, child] of Object.entries(value)) {
      if (names.has(key)) found.push(child);
      visit(child, depth + 1);
    }
  }
  visit(root, 0);
  return found;
}

function field(root, keys) { return fields(root, keys)[0]; }
function entries(root) {
  return fields(root, ['entry']).flatMap(value => Array.isArray(value) ? value : [value]).filter(value => value && typeof value === 'object');
}
function finding(metric, value, unit, severity, message, recommendation = '', extra = {}) {
  return { metric, value: value === undefined ? null : value, unit, severity, message, recommendation, ...extra };
}
function unknown(metric, extra = {}) {
  return finding(metric, null, '', 'unknown', '缺少可识别的检查证据', '核对设备支持情况及采集字段', extra);
}

module.exports = { scalar, toNumber, fields, field, entries, finding, unknown };
