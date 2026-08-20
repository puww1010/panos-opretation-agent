import { Agent, ProxyAgent, type Dispatcher } from "undici";
import { connect as tlsConnect } from "tls";
import { SocksClient } from "socks";

/**
 * Proxy support for PanOS API requests.
 *
 * Resolution order (first non-empty wins):
 *   1. PANOS_PROXY         — explicit override, used regardless of NO_PROXY
 *   2. HTTPS_PROXY / https_proxy
 *   3. HTTP_PROXY  / http_proxy
 *   4. ALL_PROXY   / all_proxy
 *
 * Supported URL schemes:
 *   - http://[user:pass@]host:port   — HTTP CONNECT proxy (undici ProxyAgent)
 *   - https://[user:pass@]host:port  — HTTPS CONNECT proxy (TLS to proxy)
 *   - socks5://[user:pass@]host:port — SOCKS5, client-side DNS
 *   - socks5h://[user:pass@]host:port — SOCKS5, proxy-side DNS (recommended)
 *   - socks4://[user@]host:port      — SOCKS4
 *   - socks4a://[user@]host:port     — SOCKS4a (proxy-side DNS)
 *
 * NO_PROXY (comma-separated): bypassed unless PANOS_PROXY is set. Entries may be
 * exact hostnames, suffixes (".example.com" or "example.com"), or "*" to bypass all.
 */

export type ProxyScheme = "http" | "https" | "socks5" | "socks5h" | "socks4" | "socks4a";

export interface ParsedProxy {
  scheme: ProxyScheme;
  host: string;
  port: number;
  username?: string;
  password?: string;
  /** Source env var the proxy came from, for diagnostics. */
  source: string;
  /** True if NO_PROXY should be ignored (PANOS_PROXY override). */
  forced: boolean;
}

const SCHEME_DEFAULT_PORT: Record<ProxyScheme, number> = {
  http: 80,
  https: 443,
  socks5: 1080,
  socks5h: 1080,
  socks4: 1080,
  socks4a: 1080,
};

/**
 * Parse a proxy URL. Returns null if the string is empty or malformed.
 * Exposed for tests.
 */
export function parseProxyUrl(raw: string, source: string, forced: boolean): ParsedProxy | null {
  if (!raw) return null;
  // Allow bare "host:port" — default to http
  const normalized = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase() as ProxyScheme;
  if (!(scheme in SCHEME_DEFAULT_PORT)) return null;
  const host = url.hostname;
  if (!host) return null;
  const port = url.port ? Number(url.port) : SCHEME_DEFAULT_PORT[scheme];
  if (!Number.isFinite(port) || port <= 0 || port > 65535) return null;
  return {
    scheme,
    host,
    port,
    username: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
    source,
    forced,
  };
}

/**
 * Resolve the active proxy from env vars. Returns null when no proxy is configured.
 */
export function resolveProxyFromEnv(env: NodeJS.ProcessEnv = process.env): ParsedProxy | null {
  const candidates: Array<{ name: string; forced: boolean }> = [
    { name: "PANOS_PROXY", forced: true },
    { name: "HTTPS_PROXY", forced: false },
    { name: "https_proxy", forced: false },
    { name: "HTTP_PROXY", forced: false },
    { name: "http_proxy", forced: false },
    { name: "ALL_PROXY", forced: false },
    { name: "all_proxy", forced: false },
  ];
  for (const { name, forced } of candidates) {
    const raw = env[name]?.trim();
    if (!raw) continue;
    const parsed = parseProxyUrl(raw, name, forced);
    if (parsed) return parsed;
  }
  return null;
}

/**
 * Return true if `host` matches an entry in NO_PROXY.
 * Supports exact match, suffix match, leading-dot suffix, and "*".
 * Exposed for tests.
 */
export function shouldBypassProxy(host: string, noProxyEnv: string | undefined): boolean {
  if (!noProxyEnv) return false;
  const target = host.toLowerCase();
  for (const rawEntry of noProxyEnv.split(",")) {
    const entry = rawEntry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === "*") return true;
    if (entry === target) return true;
    const suffix = entry.startsWith(".") ? entry : `.${entry}`;
    if (target.endsWith(suffix)) return true;
  }
  return false;
}

/**
 * Build an undici Dispatcher for a given target URL.
 * verifySSL controls TLS certificate validation for the target firewall.
 */
export function buildDispatcher(targetUrl: string, verifySSL = false, env: NodeJS.ProcessEnv = process.env): Dispatcher {
  const proxy = resolveProxyFromEnv(env);
  if (!proxy) return defaultAgent(verifySSL);

  let targetHost = "";
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    // fall through — if the URL is invalid undici will reject it anyway
  }
  if (!proxy.forced && targetHost && shouldBypassProxy(targetHost, env.NO_PROXY ?? env.no_proxy)) {
    return defaultAgent(verifySSL);
  }

  switch (proxy.scheme) {
    case "http":
    case "https":
      return buildHttpProxyAgent(proxy, verifySSL);
    case "socks5":
    case "socks5h":
    case "socks4":
    case "socks4a":
      return buildSocksAgent(proxy, verifySSL);
  }
}

function defaultAgent(verifySSL: boolean): Agent {
  return new Agent({ connect: { rejectUnauthorized: verifySSL } });
}

function buildHttpProxyAgent(proxy: ParsedProxy, verifySSL: boolean): ProxyAgent {
  const { scheme, host, port, username, password } = proxy;
  const auth = username ? `${encodeURIComponent(username)}:${encodeURIComponent(password ?? "")}@` : "";
  const uri = `${scheme}://${auth}${host}:${port}`;
  return new ProxyAgent({
    uri,
    requestTls: { rejectUnauthorized: verifySSL },
    proxyTls: { rejectUnauthorized: false },
  });
}

function buildSocksAgent(proxy: ParsedProxy, verifySSL: boolean): Agent {
  const socksType: 4 | 5 = proxy.scheme.startsWith("socks5") ? 5 : 4;
  return new Agent({
    connect: async (opts: any, callback: (err: Error | null, socket: any) => void) => {
      try {
        const hostname: string = opts.hostname ?? opts.host;
        const port: number = Number(opts.port) || (opts.protocol === "https:" ? 443 : 80);
        const { socket } = await SocksClient.createConnection({
          proxy: {
            host: proxy.host,
            port: proxy.port,
            type: socksType,
            userId: proxy.username,
            password: proxy.password,
          },
          command: "connect",
          destination: { host: hostname, port },
        });

        if (opts.protocol === "https:") {
          const tlsSock = tlsConnect({
            socket,
            servername: opts.servername || hostname,
            rejectUnauthorized: verifySSL,
            ALPNProtocols: ["http/1.1"],
          });
          tlsSock.once("secureConnect", () => callback(null, tlsSock));
          tlsSock.once("error", (err) => callback(err, null as any));
        } else {
          callback(null, socket);
        }
      } catch (err) {
        callback(err as Error, null as any);
      }
    },
  });
}

/**
 * Human-readable description of the active proxy, for logs/diagnostics.
 * Masks credentials. Returns null when no proxy is active.
 */
export function describeProxy(env: NodeJS.ProcessEnv = process.env): string | null {
  const proxy = resolveProxyFromEnv(env);
  if (!proxy) return null;
  const creds = proxy.username ? `${proxy.username}:***@` : "";
  return `${proxy.scheme}://${creds}${proxy.host}:${proxy.port} (from ${proxy.source})`;
}

