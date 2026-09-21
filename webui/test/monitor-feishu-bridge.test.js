const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

test('Feishu automatic reply uses the authenticated shared notification, without loading runtime config', () => {
  // Compile only the pure dispatch function; never import or start the daemon.
  const source = fs.readFileSync(path.join(__dirname, '../../feishu-bridge.py'), 'utf8');
  const script = `import ast, sys
tree = ast.parse(sys.stdin.read())
fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'summarize_task')
calls = []
def http_json(url):
    calls.append(url)
    return {'taskId': 19, 'text': 'TEST_SHARED_REPORT_19'}
scope = {'http_json': http_json}
exec(compile(ast.Module(body=[fn], type_ignores=[]), '<bridge-test>', 'exec'), scope)
for status in ['done', 'failed', 'cancelled']:
    assert scope['summarize_task']({'id': 19, 'type': 'monitor', 'status': status, 'result': {'monitor': {}}}) == 'TEST_SHARED_REPORT_19'
assert calls == ['/api/task/19/monitor/notification'] * 3
def unavailable(url):
    raise RuntimeError('TEST_INTERNAL_ERROR_NOT_FOR_REPORT')
scope['http_json'] = unavailable
fallback = scope['summarize_task']({'id': 19, 'type': 'monitor', 'status': 'done'})
assert '19' in fallback and 'TEST_INTERNAL_ERROR' not in fallback
legacy = scope['summarize_task']({'type': 'inspect', 'status': 'done', 'result': {'grade': '良好', 'rate': 75, 'checks': []}})
assert '75' in legacy
print('PASS')`;
  assert.equal(execFileSync('python3', ['-c', script], { input: source, encoding: 'utf8' }).trim(), 'PASS');
});

test('Feishu polling allows the monitor budget, but stays bounded and retains ordinary timeouts', () => {
  const source = fs.readFileSync(path.join(__dirname, '../../feishu-bridge.py'), 'utf8');
  const script = `import ast, sys
tree = ast.parse(sys.stdin.read())
fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'wait_task')
class Clock:
    now = 0
    def time(self): return self.now
    def sleep(self, seconds): self.now += seconds
clock = Clock()
kind, finish = 'monitor', 100
def http_json(url):
    assert url == '/api/tasks'
    return {'tasks': [{'id': 19, 'type': kind, 'status': 'done' if clock.now >= finish else 'running'}]}
scope = {'http_json': http_json, 'time': clock}
exec(compile(ast.Module(body=[fn], type_ignores=[]), '<bridge-test>', 'exec'), scope)
assert scope['wait_task'](19)['status'] == 'done'
clock.now, kind, finish = 0, 'query', 100
assert scope['wait_task'](19) is None and clock.now == 90
clock.now, kind, finish = 0, 'monitor', 1000
assert scope['wait_task'](19) is None and clock.now == 660
clock.now = 0
scope['http_json'] = lambda url: {'tasks': [{'id': 19, 'type': 'monitor', 'status': 'cancelled'}]}
assert scope['wait_task'](19)['status'] == 'cancelled' and clock.now == 0
print('PASS')`;
  assert.equal(execFileSync('python3', ['-c', script], { input: source, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim(), 'PASS');
});
