import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getFirewallEntries, isMultiFirewall } from "../config/firewalls.ts";

export function registerFirewallTools(server: McpServer) {
  server.tool(
    "list_firewalls",
    "[READ-ONLY] Lists all configured firewall targets. Shows names and hosts (never API keys). Indicates whether the 'firewall' parameter is required for other tools.",
    {},
    { title: "List Firewalls", readOnlyHint: true, destructiveHint: false },
    async () => {
      const entries = getFirewallEntries();
      const multi = isMultiFirewall();

      let mode: string;
      if (entries.length === 0) {
        mode = "environment";
      } else if (entries.length === 1) {
        mode = "single";
      } else {
        mode = "multi";
      }

      const firewalls = entries.map((e) => ({ name: e.name, host: e.host }));

      const data = {
        mode,
        firewall_param_required: multi,
        firewalls,
      };

      if (entries.length === 0) {
        const host = process.env.PANOS_HOST;
        if (host) {
          data.firewalls = [{ name: "env", host }];
        }
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }
  );
}
