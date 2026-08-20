import { describe, it, expect } from "vitest";
import {
  configXpath,
  deviceGroup,
  nlogsSchema,
  xmlElement,
  xmlCommand,
  commitDescription,
  partialAdmin,
  logQuery,
  firewallName,
} from "../../src/schemas/panos.js";

describe("configXpath", () => {
  it.each(["/config", "/config/devices/entry"])("accepts %j", (v) => {
    expect(configXpath.safeParse(v).success).toBe(true);
  });

  it.each(["", "/devices", 123, null, undefined, "prefix/config"])(
    "rejects %j",
    (v) => {
      expect(configXpath.safeParse(v).success).toBe(false);
    }
  );
});

describe("deviceGroup", () => {
  it.each(["shared", "a"])("accepts %j", (v) => {
    expect(deviceGroup.safeParse(v).success).toBe(true);
  });

  it.each(["", 42, undefined])("rejects %j", (v) => {
    expect(deviceGroup.safeParse(v).success).toBe(false);
  });
});

describe("nlogsSchema", () => {
  it.each([undefined, 1, 100, 5000])("accepts %j", (v) => {
    expect(nlogsSchema.safeParse(v).success).toBe(true);
  });

  it.each([0, -1, 5001, 2.5, "100", null])("rejects %j", (v) => {
    expect(nlogsSchema.safeParse(v).success).toBe(false);
  });
});

describe("xmlElement", () => {
  it.each(['<entry name="foo"/>', "<tag/>"])("accepts %j", (v) => {
    expect(xmlElement.safeParse(v).success).toBe(true);
  });

  it.each(["entry", "", 123])("rejects %j", (v) => {
    expect(xmlElement.safeParse(v).success).toBe(false);
  });
});

describe("xmlCommand", () => {
  it.each(["<show><system><info></info></system></show>"])("accepts %j", (v) => {
    expect(xmlCommand.safeParse(v).success).toBe(true);
  });

  it.each(["show system", ""])("rejects %j", (v) => {
    expect(xmlCommand.safeParse(v).success).toBe(false);
  });
});

describe("commitDescription", () => {
  it.each([undefined, "", "some description", "a".repeat(512)])(
    "accepts %j",
    (v) => {
      expect(commitDescription.safeParse(v).success).toBe(true);
    }
  );

  it.each(["a".repeat(513), 42])("rejects %j", (v) => {
    expect(commitDescription.safeParse(v).success).toBe(false);
  });
});

describe("partialAdmin", () => {
  it.each([undefined, "admin", "a", "a".repeat(63)])("accepts %j", (v) => {
    expect(partialAdmin.safeParse(v).success).toBe(true);
  });

  it.each(["", "a".repeat(64)])("rejects %j", (v) => {
    expect(partialAdmin.safeParse(v).success).toBe(false);
  });
});

describe("logQuery", () => {
  it.each([undefined, "", "( addr.src in 10.0.0.0/8 )", "x".repeat(2048)])(
    "accepts %j",
    (v) => {
      expect(logQuery.safeParse(v).success).toBe(true);
    }
  );

  it.each(["x".repeat(2049), 999])("rejects %j", (v) => {
    expect(logQuery.safeParse(v).success).toBe(false);
  });
});

describe("firewallName", () => {
  it.each([undefined, "fw1", "a", "a".repeat(63)])("accepts %j", (v) => {
    expect(firewallName.safeParse(v).success).toBe(true);
  });

  it.each(["", "a".repeat(64), 42, null])("rejects %j", (v) => {
    expect(firewallName.safeParse(v).success).toBe(false);
  });
});
