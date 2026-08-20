import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getConfig, setConfig, deleteConfig, moveConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName, xmlEscape } from "../schemas/panos.ts";

function members(items: string[]): string {
  return items.map(i => `<member>${xmlEscape(i)}</member>`).join("");
}

export function registerNatTools(server: McpServer) {
  server.tool(
    "get_nat_rules",
    "[READ-ONLY] Retrieves all NAT policy rules including source NAT, destination NAT, and bidirectional rules. Reads config at: /config/.../rulebase/nat/rules.",
    {
      firewall: firewallName,
    },
    { title: "Get NAT Rules", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_nat_rule",
    "[MODIFIES CONFIG] Creates a new NAT policy rule (source NAT, destination NAT, or both). Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("NAT rule name"),
      from_zones: z.array(z.string().min(1)).min(1).describe("Source zones"),
      to_zones: z.array(z.string().min(1)).min(1).describe("Destination zones"),
      source: z.array(z.string().min(1)).min(1).describe("Source addresses or 'any'"),
      destination: z.array(z.string().min(1)).min(1).describe("Destination addresses or 'any'"),
      service: z.string().min(1).describe("Service (e.g. 'any', 'service-http')"),
      snat_type: z.enum(["dynamic-ip-and-port", "dynamic-ip", "static-ip"]).optional().describe("Source NAT type"),
      snat_address: z.string().optional().describe("Source NAT translated address (address object or IP)"),
      snat_interface: z.string().optional().describe("Source NAT interface (for dynamic-ip-and-port with interface)"),
      dnat_address: z.string().optional().describe("Destination NAT translated address"),
      dnat_port: z.string().optional().describe("Destination NAT translated port"),
      description: z.string().max(1023).optional().describe("Optional description"),
      disabled: z.boolean().optional().describe("Create rule in disabled state"),
      firewall: firewallName,
    },
    { title: "Add NAT Rule", readOnlyHint: false, destructiveHint: true },
    async ({ name, from_zones, to_zones, source, destination, service, snat_type, snat_address, snat_interface, dnat_address, dnat_port, description, disabled, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules";
      let element = `<entry name="${xmlEscape(name)}">`;
      element += `<from>${members(from_zones)}</from>`;
      element += `<to>${members(to_zones)}</to>`;
      element += `<source>${members(source)}</source>`;
      element += `<destination>${members(destination)}</destination>`;
      element += `<service>${xmlEscape(service)}</service>`;
      if (snat_type) {
        element += `<source-translation>`;
        if (snat_type === "dynamic-ip-and-port") {
          element += `<dynamic-ip-and-port>`;
          if (snat_interface) {
            element += `<interface-address><interface>${xmlEscape(snat_interface)}</interface></interface-address>`;
          } else if (snat_address) {
            element += `<translated-address>${members([snat_address])}</translated-address>`;
          }
          element += `</dynamic-ip-and-port>`;
        } else if (snat_type === "dynamic-ip") {
          element += `<dynamic-ip>`;
          if (snat_address) element += `<translated-address>${members([snat_address])}</translated-address>`;
          element += `</dynamic-ip>`;
        } else if (snat_type === "static-ip") {
          element += `<static-ip>`;
          if (snat_address) element += `<translated-address>${xmlEscape(snat_address)}</translated-address>`;
          element += `</static-ip>`;
        }
        element += `</source-translation>`;
      }
      if (dnat_address) {
        element += `<destination-translation><translated-address>${xmlEscape(dnat_address)}</translated-address>`;
        if (dnat_port) element += `<translated-port>${xmlEscape(dnat_port)}</translated-port>`;
        element += `</destination-translation>`;
      }
      if (description) element += `<description>${xmlEscape(description)}</description>`;
      if (disabled !== undefined) element += `<disabled>${disabled ? "yes" : "no"}</disabled>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "move_nat_rule",
    "[MODIFIES CONFIG] Moves a NAT policy rule to a new position in the rulebase. Rule order determines evaluation priority. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Name of the NAT rule to move"),
      where: z.enum(["top", "bottom", "before", "after"]).describe("Position to move the rule to"),
      destination: z.string().optional().describe("Reference rule name (required when 'where' is 'before' or 'after')"),
      firewall: firewallName,
    },
    { title: "Move NAT Rule", readOnlyHint: false, destructiveHint: true },
    async ({ name, where, destination, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      if ((where === "before" || where === "after") && !destination) {
        return formatResponse({ success: false, error: "'destination' is required when 'where' is 'before' or 'after'" });
      }
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name='${name}']`;
      const result = await moveConfig(xpath, where, destination, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_nat_rule",
    "[MODIFIES CONFIG] Deletes a NAT policy rule. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Rule name to delete"),
      firewall: firewallName,
    },
    { title: "Delete NAT Rule", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "set_nat_rule_disabled",
    "[MODIFIES CONFIG] Enables or disables a NAT policy rule. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Rule name"),
      disabled: z.boolean().describe("true to disable the rule, false to enable it"),
      firewall: firewallName,
    },
    { title: "Set NAT Rule Disabled", readOnlyHint: false, destructiveHint: true },
    async ({ name, disabled, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name='${name}']`;
      const element = `<disabled>${disabled ? "yes" : "no"}</disabled>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );
}
