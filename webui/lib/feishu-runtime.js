const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

function executable(file) {
  try { fs.accessSync(file, fs.constants.X_OK); return fs.statSync(file).isFile(); }
  catch { return false; }
}

function resolveFeishuRuntime({ environment = process.env, homeDirectory = os.homedir(), nodeExecutable = process.execPath } = {}) {
  let cli = environment.LARK_CLI;
  if (!cli) {
    cli = (environment.PATH || "").split(path.delimiter).filter(Boolean)
      .map(directory => path.resolve(directory, "lark-cli")).find(executable);
    const bundled = path.join(homeDirectory, ".workbuddy/binaries/node/cli-connector-packages/bin/lark-cli");
    if (!cli && executable(bundled)) cli = bundled;
  }
  cli = cli || "lark-cli";
  const directories = [path.dirname(nodeExecutable), path.isAbsolute(cli) ? path.dirname(cli) : "", environment.PATH];
  return { cli, env: { ...environment, PATH: directories.filter(Boolean).join(path.delimiter) } };
}

module.exports = { resolveFeishuRuntime };
