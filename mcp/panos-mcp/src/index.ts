#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadFirewallConfig } from "./config/firewalls.ts";
import { isKeychainAvailable } from "./config/keychain.ts";
import { describeProxy } from "./api/proxy.ts";

import { registerFirewallTools } from "./tools/firewalls.ts";
import { registerSystemTools } from "./tools/system.ts";
import { registerNetworkTools } from "./tools/network.ts";
import { registerSecurityTools } from "./tools/security.ts";
import { registerObjectsTools } from "./tools/objects.ts";
import { registerNatTools } from "./tools/nat.ts";
import { registerUserIdTools } from "./tools/userid.ts";
import { registerAdminTools } from "./tools/admin.ts";
import { registerVpnTools } from "./tools/vpn.ts";
import { registerPanoramaTools } from "./tools/panorama.ts";
import { registerLogsTools } from "./tools/logs.ts";
import { registerThreatTools } from "./tools/threat.ts";
import { registerCertificatesTools } from "./tools/certificates.ts";
import { registerLicensesTools } from "./tools/licenses.ts";
import { registerConfigTools } from "./tools/config.ts";
import { registerUtilityTools } from "./tools/utility.ts";

const server = new McpServer({
  name: "panos-mcp",
  version: "1.3.29",
});

// Wrap all tool handlers to catch unexpected errors cleanly
const _tool = server.tool.bind(server);
(server.tool as any) = function (...args: any[]) {
  const last = args.length - 1;
  const handler = args[last];
  args[last] = async (...hArgs: any[]) => {
    try {
      return await handler(...hArgs);
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
      };
    }
  };
  return (_tool as (...a: any[]) => any)(...args);
};

// Register all tools
registerFirewallTools(server);
registerSystemTools(server);
registerNetworkTools(server);
registerSecurityTools(server);
registerObjectsTools(server);
registerNatTools(server);
registerUserIdTools(server);
registerAdminTools(server);
registerVpnTools(server);
registerPanoramaTools(server);
registerLogsTools(server);
registerThreatTools(server);
registerCertificatesTools(server);
registerLicensesTools(server);
registerConfigTools(server);
registerUtilityTools(server);

async function main() {
  await loadFirewallConfig();
  if (!isKeychainAvailable()) {
    process.stderr.write(
      "[panos-mcp] WARNING: System keychain unavailable — API keys are stored in plaintext. " +
      "Install a keychain provider (macOS Keychain, libsecret on Linux, Windows Credential Manager) " +
      "and re-run `panos-mcp keygen` to migrate keys to secure storage.\n"
    );
  }
  const proxy = describeProxy();
  if (proxy) {
    console.error(`PanOS proxy: ${proxy}`);
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
