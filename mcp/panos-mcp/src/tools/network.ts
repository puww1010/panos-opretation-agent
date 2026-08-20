import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { executeOpCommand, getConfig, setConfig, deleteConfig, formatResponse, resolveTarget, isApiError } from "../api/client.ts";
import { firewallName, xmlEscape } from "../schemas/panos.ts";

export function registerNetworkTools(server: McpServer) {
  server.tool(
    "get_interfaces",
    "[READ-ONLY] Retrieves all network interfaces with their status, IP addresses, and configuration. Executes: show interface all.",
    {
      firewall: firewallName,
    },
    { title: "Get Interfaces", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><interface>all</interface></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_zones",
    "[READ-ONLY] Retrieves all security zones configured on the firewall. Reads config at: /config/.../vsys/entry/zone.",
    {
      firewall: firewallName,
    },
    { title: "Get Zones", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_routing_table",
    "[READ-ONLY] Retrieves the current routing table from the firewall. Executes: show routing route.",
    {
      firewall: firewallName,
    },
    { title: "Get Routing Table", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><routing><route></route></routing></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_arp_table",
    "[READ-ONLY] Retrieves ARP table entries from the firewall. Executes: show arp entry all.",
    {
      firewall: firewallName,
    },
    { title: "Get ARP Table", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><arp><entry name='all'/></arp></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_vlans",
    "[READ-ONLY] Retrieves VLAN configuration from the firewall. Reads config at: /config/.../network/vlan.",
    {
      firewall: firewallName,
    },
    { title: "Get VLANS", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/network/vlan", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_dhcp_leases",
    "[READ-ONLY] Retrieves DHCP server lease information. Executes: show dhcp server lease all.",
    {
      firewall: firewallName,
    },
    { title: "Get DHCP Leases", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await executeOpCommand("<show><dhcp><server><lease>all</lease></server></dhcp></show>", target);
      return formatResponse(result);
    }
  );

  server.tool(
    "get_dns_proxy",
    "[READ-ONLY] Retrieves DNS proxy configuration. Reads config at: /config/.../network/dns-proxy.",
    {
      firewall: firewallName,
    },
    { title: "Get DNS Proxy", readOnlyHint: true, destructiveHint: false },
    async ({ firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const result = await getConfig("/config/devices/entry[@name='localhost.localdomain']/network/dns-proxy", target);
      return formatResponse(result);
    }
  );

  // Static Routes

  server.tool(
    "get_static_routes",
    "[READ-ONLY] Retrieves static routes from a virtual router. Reads config at: /config/.../virtual-router/entry/routing-table/ip/static-route.",
    {
      virtual_router: z.string().min(1).max(63).optional().describe("Virtual router name (default: 'default')"),
      firewall: firewallName,
    },
    { title: "Get Static Routes", readOnlyHint: true, destructiveHint: false },
    async ({ virtual_router, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const vr = virtual_router || "default";
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='${vr}']/routing-table/ip/static-route`;
      const result = await getConfig(xpath, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "add_static_route",
    "[MODIFIES CONFIG] Creates a static route in a virtual router. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Static route name"),
      destination: z.string().min(1).describe("Destination CIDR (e.g. '10.0.0.0/8', '0.0.0.0/0')"),
      nexthop_type: z.enum(["ip-address", "next-vr", "none"]).describe("Next-hop type"),
      nexthop_value: z.string().optional().describe("Next-hop IP address or virtual router name (required for ip-address and next-vr types)"),
      interface: z.string().optional().describe("Egress interface (e.g. 'ethernet1/1')"),
      metric: z.number().int().min(1).max(65535).optional().describe("Route metric (default: 10)"),
      virtual_router: z.string().min(1).max(63).optional().describe("Virtual router name (default: 'default')"),
      firewall: firewallName,
    },
    { title: "Add Static Route", readOnlyHint: false, destructiveHint: true },
    async ({ name, destination, nexthop_type, nexthop_value, interface: iface, metric, virtual_router, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const vr = virtual_router || "default";
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='${vr}']/routing-table/ip/static-route`;
      let element = `<entry name="${xmlEscape(name)}">`;
      element += `<destination>${xmlEscape(destination)}</destination>`;
      if (nexthop_type === "ip-address" && nexthop_value) {
        element += `<nexthop><ip-address>${xmlEscape(nexthop_value)}</ip-address></nexthop>`;
      } else if (nexthop_type === "next-vr" && nexthop_value) {
        element += `<nexthop><next-vr>${xmlEscape(nexthop_value)}</next-vr></nexthop>`;
      } else if (nexthop_type === "none") {
        element += `<nexthop><none/></nexthop>`;
      }
      if (iface) element += `<interface>${xmlEscape(iface)}</interface>`;
      if (metric !== undefined) element += `<metric>${metric}</metric>`;
      element += `</entry>`;
      const result = await setConfig(xpath, element, target);
      return formatResponse(result);
    }
  );

  server.tool(
    "delete_static_route",
    "[MODIFIES CONFIG] Deletes a static route from a virtual router. Staged in candidate config — requires 'commit' to activate.",
    {
      name: z.string().min(1).max(63).describe("Static route name to delete"),
      virtual_router: z.string().min(1).max(63).optional().describe("Virtual router name (default: 'default')"),
      firewall: firewallName,
    },
    { title: "Delete Static Route", readOnlyHint: false, destructiveHint: true },
    async ({ name, virtual_router, firewall }) => {
      const target = resolveTarget(firewall);
      if (isApiError(target)) return formatResponse(target);
      const vr = virtual_router || "default";
      const xpath = `/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='${vr}']/routing-table/ip/static-route/entry[@name='${name}']`;
      const result = await deleteConfig(xpath, target);
      return formatResponse(result);
    }
  );
}
