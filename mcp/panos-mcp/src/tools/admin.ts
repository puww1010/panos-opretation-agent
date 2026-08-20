import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName } from "../schemas/panos.ts";

export function registerAdminTools(server: McpServer) {
  server.tool(
    "get_admins",
    "[READ-ONLY] Retrieves all administrator accounts configured on the firewall. Reads config at: /config/mgt-config/users.",
    {
      firewall: firewallName,
    },
    { title: "Get Admins", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/mgt-config/users", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_admin_roles",
    "[READ-ONLY] Retrieves administrator role definitions and their permissions. Reads config at: /config/.../vsys/entry/admin-role.",
    {
      firewall: firewallName,
    },
    { title: "Get Admin Roles", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/admin-role", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_auth_profiles",
    "[READ-ONLY] Retrieves authentication profiles including RADIUS, LDAP, and TACACS+ configurations. Reads config at: /config/shared/authentication-profile.",
    {
      firewall: firewallName,
    },
    { title: "Get Auth Profiles", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/shared/authentication-profile", target);
      return formatResponse(result);
    }
  );
}
