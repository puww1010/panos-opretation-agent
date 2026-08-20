import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { executeOpCommand, getConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName } from "../schemas/panos.ts";

export function registerVpnTools(server: McpServer) {
  server.tool(
    "get_ipsec_tunnels",
    "[READ-ONLY] Retrieves IPSec VPN tunnel status and security associations. Executes: show vpn ipsec-sa.",
    {
      firewall: firewallName,
    },
    { title: "Get IPSec Tunnels", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><vpn><ipsec-sa></ipsec-sa></vpn></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_globalprotect_users",
    "[READ-ONLY] Retrieves currently connected GlobalProtect VPN users. Executes: show global-protect-gateway current-user.",
    {
      firewall: firewallName,
    },
    { title: "Get GlobalProtect Users", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_globalprotect_config",
    "[READ-ONLY] Retrieves GlobalProtect gateway and portal configuration. Reads config at: /config/.../vsys/entry/global-protect.",
    {
      firewall: firewallName,
    },
    { title: "Get GlobalProtect Config", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect", target);
      return formatResponse(result);
    }
  );
}
