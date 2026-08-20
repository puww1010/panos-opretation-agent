import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getConfig, setConfig, deleteConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName, xmlEscape } from "../schemas/panos.ts";

function members(items: string[]): string {
  return items.map(i => `<member>${xmlEscape(i)}</member>`).join("");
}

export function registerObjectsTools(server: McpServer) {
  server.tool(
    "get_address_objects",
    "[READ-ONLY] Retrieves all address objects (IP addresses, ranges, FQDNs) defined on the firewall. Reads config at: /config/.../vsys/entry/address.",
    {
      firewall: firewallName,
    },
    { title: "Get Address Objects", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_address_groups",
    "[READ-ONLY] Retrieves all address groups that contain multiple address objects. Reads config at: /config/.../vsys/entry/address-group.",
    {
      firewall: firewallName,
    },
    { title: "Get Address Groups", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_service_objects",
    "[READ-ONLY] Retrieves all service objects (port/protocol definitions) from the firewall. Reads config at: /config/.../vsys/entry/service.",
    {
      firewall: firewallName,
    },
    { title: "Get Service Objects", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_service_groups",
    "[READ-ONLY] Retrieves all service groups that contain multiple service objects. Reads config at: /config/.../vsys/entry/service-group.",
    {
      firewall: firewallName,
    },
    { title: "Get Service Groups", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_application_filters",
    "[READ-ONLY] Retrieves application filters used for application-based policy rules. Reads config at: /config/.../vsys/entry/application-filter.",
    {
      firewall: firewallName,
    },
    { title: "Get Application Filters", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/application-filter", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_address_object",
    "[MODIFIES CONFIG] Creates an address object (IP/netmask, IP range, or FQDN). Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Address object name"),
      type: z.enum(["ip-netmask", "ip-range", "fqdn"]).describe("Address type"),
      value: z.string().min(1).describe("Address value (e.g. '10.0.0.0/24', '10.0.0.1-10.0.0.10', 'example.com')"),
      description: z.string().max(1023).optional().describe("Optional description"),
      firewall: firewallName,
    },
    { title: "Add Address Object", readOnlyHint: false, destructiveHint: true },
    async ({ name, type, value, description, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address";
      let element = `<entry name="${xmlEscape(name)}"><${type}>${xmlEscape(value)}</${type}>`;
      if (description) element += `<description>${xmlEscape(description)}</description>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_address_group",
    "[MODIFIES CONFIG] Creates a static address group containing one or more address objects. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Address group name"),
      members: z.array(z.string().min(1)).min(1).describe("List of address object names to include"),
      description: z.string().max(1023).optional().describe("Optional description"),
      firewall: firewallName,
    },
    { title: "Add Address Group", readOnlyHint: false, destructiveHint: true },
    async ({ name, members: memberList, description, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group";
      let element = `<entry name="${xmlEscape(name)}"><static>${members(memberList)}</static>`;
      if (description) element += `<description>${xmlEscape(description)}</description>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_service_object",
    "[MODIFIES CONFIG] Creates a TCP or UDP service object with a port or port range. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Service object name"),
      protocol: z.enum(["tcp", "udp"]).describe("Protocol"),
      port: z.string().min(1).describe("Port number or range (e.g. '443', '8000-8080')"),
      description: z.string().max(1023).optional().describe("Optional description"),
      firewall: firewallName,
    },
    { title: "Add Service Object", readOnlyHint: false, destructiveHint: true },
    async ({ name, protocol, port, description, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service";
      let element = `<entry name="${xmlEscape(name)}"><protocol><${protocol}><port>${xmlEscape(port)}</port></${protocol}></protocol>`;
      if (description) element += `<description>${xmlEscape(description)}</description>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_service_group",
    "[MODIFIES CONFIG] Creates a service group containing one or more service objects. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Service group name"),
      members: z.array(z.string().min(1)).min(1).describe("List of service object names to include"),
      description: z.string().max(1023).optional().describe("Optional description"),
      firewall: firewallName,
    },
    { title: "Add Service Group", readOnlyHint: false, destructiveHint: true },
    async ({ name, members: memberList, description, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group";
      let element = `<entry name="${xmlEscape(name)}"><members>${members(memberList)}</members>`;
      if (description) element += `<description>${xmlEscape(description)}</description>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_address_object",
    "[MODIFIES CONFIG] Deletes an address object. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Address object name to delete"),
      firewall: firewallName,
    },
    { title: "Delete Address Object", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_address_group",
    "[MODIFIES CONFIG] Deletes an address group. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Address group name to delete"),
      firewall: firewallName,
    },
    { title: "Delete Address Group", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_service_object",
    "[MODIFIES CONFIG] Deletes a service object. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Service object name to delete"),
      firewall: firewallName,
    },
    { title: "Delete Service Object", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_service_group",
    "[MODIFIES CONFIG] Deletes a service group. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Service group name to delete"),
      firewall: firewallName,
    },
    { title: "Delete Service Group", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );

  // Tags

  server.tool(
    "get_tags",
    "[READ-ONLY] Retrieves all tags defined on the firewall. Reads config at: /config/.../vsys/entry/tag.",
    {
      firewall: firewallName,
    },
    { title: "Get Tags", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_tag",
    "[MODIFIES CONFIG] Creates a tag object. Tags can be applied to rules, objects, and other configuration elements. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(127).describe("Tag name"),
      color: z.enum([
        "color1", "color2", "color3", "color4", "color5", "color6", "color7", "color8",
        "color9", "color10", "color11", "color12", "color13", "color14", "color15", "color16"
      ]).optional().describe("Tag color (color1=Red, color2=Green, color3=Blue, color4=Yellow, color5=Copper, color6=Orange, color7=Purple, color8=Gray, color9=Light Green, color10=Cyan, color11=Light Gray, color12=Blue Gray, color13=Lime, color14=Black, color15=Gold, color16=Brown)"),
      comments: z.string().max(1023).optional().describe("Optional comments"),
      firewall: firewallName,
    },
    { title: "Add Tag", readOnlyHint: false, destructiveHint: true },
    async ({ name, color, comments, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag";
      let element = `<entry name="${xmlEscape(name)}">`;
      if (color) element += `<color>${color}</color>`;
      if (comments) element += `<comments>${xmlEscape(comments)}</comments>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_tag",
    "[MODIFIES CONFIG] Deletes a tag object. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(127).describe("Tag name to delete"),
      firewall: firewallName,
    },
    { title: "Delete Tag", readOnlyHint: false, destructiveHint: true },
    async ({ name, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );
}
