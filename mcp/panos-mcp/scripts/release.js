import { readFileSync, writeFileSync } from "fs";
import { spawnSync } from "child_process";

const bumpType = process.argv[2] || "patch";
if (!["patch", "minor", "major"].includes(bumpType)) {
  console.error(`Unknown bump type "${bumpType}". Use patch, minor, or major.`);
  process.exit(1);
}

function run(command, args, opts = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...opts });
  if (result.status !== 0) process.exit(result.status ?? 1);
  return result;
}

function runCapture(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return { status: result.status ?? 1, stdout: (result.stdout || "").trim() };
}

const status = runCapture("git", ["status", "--porcelain"]);
if (status.stdout.length > 0) {
  console.error("Working tree is not clean. Commit or stash changes before releasing.");
  process.exit(1);
}

const oldVersion = JSON.parse(readFileSync("package.json", "utf8")).version;
const oldTag = `v${oldVersion}`;

const log = runCapture("git", ["log", `${oldTag}..HEAD`, "--oneline"]);
const changelog = log.status === 0 && log.stdout.length > 0
  ? log.stdout
  : "(no commits found since previous tag)";

run("npm", ["version", bumpType, "--no-git-tag-version"]);
const newVersion = JSON.parse(readFileSync("package.json", "utf8")).version;
const newTag = `v${newVersion}`;

for (const file of ["manifest.json", "src/index.ts"]) {
  const contents = readFileSync(file, "utf8");
  writeFileSync(file, contents.replace(`"${oldVersion}"`, `"${newVersion}"`));
}

run("npm", ["run", "pack:extension"]);

run("git", ["add", "package.json", "package-lock.json", "manifest.json", "src/index.ts"]);
run("git", ["commit", "-m", `chore: release ${newTag}\n\n${changelog}`]);
run("git", ["tag", newTag]);
run("git", ["push", "origin", "main"]);
run("git", ["push", "origin", newTag]);

const oldRelease = runCapture("gh", ["release", "view", oldTag]);
if (oldRelease.status === 0) {
  run("gh", ["release", "delete", oldTag, "--yes"]);
}

run("gh", [
  "release", "create", newTag, "panos-mcp.mcpb",
  "--title", newTag,
  "--notes", `Changes since ${oldTag}:\n\n${changelog}`,
]);

console.log(`Released ${newTag}`);
