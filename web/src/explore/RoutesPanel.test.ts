import { describe, expect, it } from "vitest";
import { isAddress } from "./RoutesPanel";

describe("isAddress", () => {
  it("accepts a complete IPv4 or IPv6 address", () => {
    for (const ok of ["10.1.2.7", "0.0.0.0", "255.255.255.255", "2001:db8::1", "::", "::ffff:10.1.2.3"]) {
      expect(isAddress(ok), ok).toBe(true);
    }
  });

  it("rejects what the server rejects", () => {
    for (const bad of ["999.1.1.1", "10.1.2", "2001:db8:", ":", "10.1.2.7/24", "fe80::1%eth0", "host"]) {
      expect(isAddress(bad), bad).toBe(false);
    }
  });
});
