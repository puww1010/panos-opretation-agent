const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const vm = require('node:vm');
const { resolveFeishuRuntime } = require('../lib/feishu-runtime');

function fixture(t) {
  const homeDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'feishu-runtime-'));
  t.after(() => fs.rmSync(homeDirectory, { recursive: true, force: true }));
  const bundled = path.join(homeDirectory, '.workbuddy/binaries/node/cli-connector-packages/bin/lark-cli');
  const installed = path.join(homeDirectory, 'system-bin/lark-cli');
  function executable(file, mode = 0o755) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({ok:true,args:process.argv.slice(2)}));\n', { mode });
  }
  return { homeDirectory, bundled, installed, executable };
}

test('explicit LARK_CLI is preserved without falling back to a different installation', t => {
  const f = fixture(t); f.executable(f.bundled);
  const explicit = path.join(f.homeDirectory, 'configured cli');
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: { PATH: '', LARK_CLI: explicit } });
  assert.equal(result.cli, explicit);
});

test('PATH installation takes priority over the optional bundled installation', t => {
  const f = fixture(t); f.executable(f.installed); f.executable(f.bundled);
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: { PATH: path.dirname(f.installed) } });
  assert.equal(result.cli, f.installed);
});

test('installed CLI is found even when the service PATH does not contain it', t => {
  const f = fixture(t); f.executable(f.bundled);
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: { PATH: '' } });
  assert.equal(result.cli, f.bundled);
});

test('non-executable files and directories are not selected as automatic CLI candidates', t => {
  const f = fixture(t); f.executable(f.installed, 0o644);
  fs.mkdirSync(f.bundled, { recursive: true });
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: { PATH: path.dirname(f.installed) } });
  assert.equal(result.cli, 'lark-cli');
});

test('missing optional CLI leaves the console startable without installing dependencies', t => {
  const f = fixture(t);
  assert.equal(resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: {} }).cli, 'lark-cli');
});

test('child environment retains settings without modifying the parent environment', t => {
  const f = fixture(t); f.executable(f.bundled);
  const environment = { PATH: '/usr/bin', TEST_SETTING: 'fixture-only' };
  const before = { ...environment };
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment });
  assert.deepEqual(environment, before);
  assert.notEqual(result.env, environment);
  assert.equal(result.env.TEST_SETTING, 'fixture-only');
  assert.equal(result.env.PATH.split(path.delimiter)[0], path.dirname(process.execPath));
});

test('resolved runtime actually starts a Node CLI with an otherwise empty PATH', t => {
  const f = fixture(t); f.executable(f.bundled);
  const result = resolveFeishuRuntime({ homeDirectory: f.homeDirectory, environment: { PATH: '' } });
  // This executable only echoes fixture arguments; it never contacts Feishu.
  const output = execFileSync(result.cli, ['fixture-check'], { env: result.env, encoding: 'utf8', timeout: 5000 });
  assert.deepEqual(JSON.parse(output), { ok: true, args: ['fixture-check'] });
});

test('application sender passes the resolved environment to the actual child process', async t => {
  const f = fixture(t); f.executable(f.bundled);
  fs.writeFileSync(f.bundled, '#!/usr/bin/env node\nif(process.env.FEISHU_RUNTIME_TEST !== "fixture") process.exit(7);\nconst a=process.argv.slice(2); if(a[0]!=="im" || a[1]!=="+messages-send" || a[3]!=="TEST_CHAT_NOT_REAL" || a[7]!=="TEST_MESSAGE_NOT_SENT") process.exit(8);\nprocess.stdout.write(JSON.stringify({ok:true,data:{message_id:"fixture-message"}}));\n');
  const source = fs.readFileSync(path.join(__dirname, '../app.js'), 'utf8');
  const start = source.indexOf('const { execFile } = require("child_process");');
  const end = source.indexOf('const taskPlanner =', start);
  assert.ok(start >= 0 && end > start);
  const environment = { PATH: '', LARK_CLI: f.bundled, FEISHU_CHAT_ID: 'TEST_CHAT_NOT_REAL', FEISHU_RUNTIME_TEST: 'fixture' };
  const evaluate = block => vm.runInNewContext(block + '\nfeishuSend;', {
    require, fs, path, process: { env: environment },
    resolveFeishuRuntime: () => resolveFeishuRuntime({ environment, homeDirectory: f.homeDirectory }),
  });
  const block = source.slice(start, end);
  const result = await evaluate(block)('TEST_MESSAGE_NOT_SENT');
  assert.equal(result.ok, true);
  assert.equal(result.data, 'fixture-message');
  const missingChildEnvironment = block.replace(', env: feishuRuntime.env', '');
  assert.notEqual(missingChildEnvironment, block);
  assert.equal((await evaluate(missingChildEnvironment)('TEST_MESSAGE_NOT_SENT')).ok, false);
});
