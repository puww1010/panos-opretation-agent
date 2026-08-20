import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { executeOpCommand, getConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName } from "../schemas/panos.ts";

export function registerUserIdTools(server: McpServer) {
  server.tool(
    "get_userid_mappings",
    "[READ-ONLY] Retrieves IP-to-user mappings from User-ID, showing which users are mapped to which IP addresses. Executes: show user ip-user-mapping all.",
    {
      firewall: firewallName,
    },
    { title: "Get User-ID Mappings", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_userid_groups",
    "[READ-ONLY] Retrieves user groups known to the firewall via User-ID. Executes: show user group list.",
    {
      firewall: firewallName,
    },
    { title: "Get User-ID Groups", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><user><group><list></list></group></user></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_userid_config",
    "[READ-ONLY] Retrieves User-ID configuration settings including agent configuration and group mapping. Reads config at: /config/.../vsys/entry/user-id-agent.",
    {
      firewall: firewallName,
    },
    { title: "Get User-ID Config", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/user-id-agent", target);
      return formatResponse(result);
    }
  );
}
