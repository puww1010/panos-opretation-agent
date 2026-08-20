import { describe, it, expect } from "vitest";
import {
  parseProxyUrl,
  resolveProxyFromEnv,
  shouldBypassProxy,
  describeProxy,
} from "../../src/api/proxy.js";

describe("parseProxyUrl", () => {
  it("parses socks5h with credentials", () => {
    const p = parseProxyUrl("socks5h://user:p%40ss@10.0.1.168:2080", "PANOS_PROXY", true);
    expect(p).toEqual({
      scheme: "socks5h",
      host: "10.0.1.168",
      port: 2080,
      username: "user",
      password: "p@ss",
      source: "PANOS_PROXY",
      forced: true,
    });
  });

  it("parses http without credentials", () => {
    const p = parseProxyUrl("http://proxy.example.com:3128", "HTTP_PROXY", false);
    expect(p).toMatchObject({ scheme: "http", host: "proxy.example.com", port: 3128 });
    expect(p?.username).toBeUndefined();
  });

  it("applies default port per scheme", () => {
    expect(parseProxyUrl("socks5://proxy.example.com", "X", false)?.port).toBe(1080);
    expect(parseProxyUrl("http://proxy.example.com", "X", false)?.port).toBe(80);
    expect(parseProxyUrl("https://proxy.example.com", "X", false)?.port).toBe(443);
  });

  it("treats bare host:port as http", () => {
    expect(parseProxyUrl("10.0.1.168:2080", "X", false)).toMatchObject({
      scheme: "http",
      host: "10.0.1.168",
      port: 2080,
    });
  });

  it("rejects unknown schemes", () => {
    expect(parseProxyUrl("ftp://proxy:21", "X", false)).toBeNull();
  });

  it("rejects malformed URLs", () => {
    expect(parseProxyUrl("", "X", false)).toBeNull();
    expect(parseProxyUrl("not a url", "X", false)).toBeNull();
  });

  it("rejects invalid ports", () => {
    expect(parseProxyUrl("http://proxy:99999", "X", false)).toBeNull();
  });
});

describe("resolveProxyFromEnv", () => {
  it("prefers PANOS_PROXY over standard vars and marks it forced", () => {
    const p = resolveProxyFromEnv({
      PANOS_PROXY: "socks5h://10.0.1.168:2080",
      HTTPS_PROXY: "http://other:3128",
    });
    expect(p?.source).toBe("PANOS_PROXY");
    expect(p?.forced).toBe(true);
    expect(p?.scheme).toBe("socks5h");
  });

  it("falls back to HTTPS_PROXY, then HTTP_PROXY, then ALL_PROXY", () => {
    expect(resolveProxyFromEnv({ HTTPS_PROXY: "http://h:1" })?.source).toBe("HTTPS_PROXY");
    expect(resolveProxyFromEnv({ HTTP_PROXY: "http://h:1" })?.source).toBe("HTTP_PROXY");
    expect(resolveProxyFromEnv({ ALL_PROXY: "socks5://h:1" })?.source).toBe("ALL_PROXY");
  });

  it("honors lowercase variants", () => {
    expect(resolveProxyFromEnv({ https_proxy: "http://h:1" })?.source).toBe("https_proxy");
  });

  it("returns null when no env var is set", () => {
    expect(resolveProxyFromEnv({})).toBeNull();
  });

  it("ignores whitespace-only values", () => {
    expect(resolveProxyFromEnv({ HTTPS_PROXY: "   " })).toBeNull();
  });

  it("marks non-PANOS_PROXY sources as non-forced", () => {
    expect(resolveProxyFromEnv({ HTTPS_PROXY: "http://h:1" })?.forced).toBe(false);
  });
});

describe("shouldBypassProxy", () => {
  it("matches exact hostname", () => {
    expect(shouldBypassProxy("example.com", "example.com")).toBe(true);
  });

  it("matches suffix with leading dot", () => {
    expect(shouldBypassProxy("api.example.com", ".example.com")).toBe(true);
  });

  it("matches suffix without leading dot", () => {
    expect(shouldBypassProxy("api.example.com", "example.com")).toBe(true);
  });

  it("does not match partial tokens", () => {
    expect(shouldBypassProxy("notexample.com", "example.com")).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(shouldBypassProxy("API.Example.COM", "example.com")).toBe(true);
  });

  it("supports comma-separated list", () => {
    expect(shouldBypassProxy("foo.internal", "localhost, .internal , 10.0.0.0/8")).toBe(true);
  });

  it("wildcard bypasses everything", () => {
    expect(shouldBypassProxy("any.host.com", "*")).toBe(true);
  });

  it("returns false for empty NO_PROXY", () => {
    expect(shouldBypassProxy("example.com", undefined)).toBe(false);
    expect(shouldBypassProxy("example.com", "")).toBe(false);
  });
});

describe("describeProxy", () => {
  it("formats with masked credentials", () => {
    expect(
      describeProxy({ PANOS_PROXY: "socks5h://alice:secret@10.0.1.168:2080" })
    ).toBe("socks5h://alice:***@10.0.1.168:2080 (from PANOS_PROXY)");
  });

  it("formats without creds when none present", () => {
    expect(describeProxy({ HTTPS_PROXY: "http://proxy:3128" })).toBe(
      "http://proxy:3128 (from HTTPS_PROXY)"
    );
  });

  it("returns null when no proxy configured", () => {
    expect(describeProxy({})).toBeNull();
  });
});
