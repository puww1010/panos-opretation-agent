import { cpSync, rmSync } from "fs";
import { spawnSync } from "child_process";

// Copy manifest, icon, and license into the extension directory
cpSync("manifest.json", "extension/manifest.json");
cpSync("icon.png", "extension/icon.png");
cpSync("LICENSE", "extension/LICENSE");

// Create .mcpb zip from extension/ contents (no shell — cwd handles the directory)
const result = spawnSync("zip", ["-r", "../panos-mcp.mcpb", "manifest.json", "icon.png", "LICENSE", "server/index.cjs"], {
  cwd: "extension",
  stdio: "inherit",
});
if (result.status !== 0) process.exit(result.status ?? 1);

// Clean up the extension directory
rmSync("extension", { recursive: true, force: true });

console.log("Packaged: panos-mcp.mcpb");
