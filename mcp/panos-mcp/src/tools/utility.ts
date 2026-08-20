import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { executeOpCommand, getConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { configXpath, xmlCommand, firewallName } from "../schemas/panos.ts";

export function registerUtilityTools(server: McpServer) {
  server.tool(
    "run_op_command",
    "[ADVANCED] Executes an arbitrary PanOS operational XML command. The command will be sent directly to the firewall API. Use with caution — the command could be read-only or state-modifying depending on its content.",
    {
      command: xmlCommand.describe("XML operational command to execute (e.g., '<show><system><info></info></system></show>')"),
      firewall: firewallName,
    },
    { title: "Run Op Command", readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    async ({ command, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand(command, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_config_xpath",
    "[READ-ONLY] Retrieves configuration at a specific XPath location. This is a flexible read tool for querying any part of the PanOS configuration tree.",
    {
      xpath: configXpath.describe("XPath to the configuration element (e.g., '/config/devices/entry[@name=\"localhost.localdomain\"]/network')"),
      firewall: firewallName,
    },
    { title: "Get Config XPath", readOnlyHint: true, destructiveHint: false },
    async ({ xpath, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig(xpath, target);
      return formatResponse(result);
    }
  );
}
