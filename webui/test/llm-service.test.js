const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { createLlmService } = require("../services/llm-service");

function serviceFiles(t, config = {}, choice = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "panos-llm-service-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const configFile = path.join(directory, "llm-config.json");
  const choiceFile = path.join(directory, "llm-choice.json");
  fs.writeFileSync(configFile, JSON.stringify(config));
  fs.writeFileSync(choiceFile, JSON.stringify(choice));
  return { configFile, choiceFile };
}

test("LLM service restores the selected provider and never exposes its key", (t) => {
  const { configFile, choiceFile } = serviceFiles(t, {
    _default: "deepseek",
    providers: { deepseek: { model: "test-model", key: "test-secret-key" } },
  }, { current: "deepseek" });
  const service = createLlmService({ configFile, choiceFile, environment: {} });

  assert.equal(service.getCurrent(), "deepseek");
  assert.equal(service.getModel(), "test-model");
  const provider = service.getPublicConfig().providers.deepseek;
  assert.equal(provider.configured, true);
  assert.equal(provider.key_hint, "test***key");
  assert.equal(Object.hasOwn(provider, "key"), false);
});

test("LLM service includes same-conversation context, parses the action, and records a bounded decision log", async (t) => {
  const { configFile, choiceFile } = serviceFiles(t, {
    providers: { deepseek: { model: "test-model", key: "test-key" } },
  }, { current: "deepseek" });
  const requests = [];
  const service = createLlmService({
    configFile,
    choiceFile,
    environment: {},
    taskLister: () => [{
      id: 1, type: "query", status: "done", conversationId: "conv-1", input: "查询旧策略",
      result: { summary: "发现 allow-web", results: [{ data: [{ "@_name": "allow-web" }] }] },
    }],
    fetcher: async (_url, options) => {
      requests.push(JSON.parse(options.body));
      return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: '{"action":"security","minutes":null}' } }] }) };
    },
  });

  const result = await service.resolveAction("查看那条策略", {
    conversationId: "conv-1",
    actions: { security: { label: "安全策略", keywords: ["策略"] } },
  });

  assert.deepEqual(result, { action: "security", minutes: null });
  assert.match(requests[0].messages[1].content, /allow-web/);
  assert.equal(service.getLogs().length, 1);
  assert.equal(service.getLogs()[0].role, "意图规划");
});
