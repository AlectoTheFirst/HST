// @vitest-environment node
//
// The symbols against the server's role vocabulary.
import { describe, expect, it } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here
import { readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here
import { fileURLToPath } from "url";
import { SYMBOL_ROLES, symbolOf } from ".";

function read(path: string): string {
  return readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8") as string;
}

describe("the device symbols", () => {
  it("give every device role and every tier role a symbol", () => {
    const labels = read("../../../../../src/hst/core/labels.py");
    const roles = [...(labels.split("DEVICE_ROLES = frozenset(")[1] ?? "").split(")")[0].matchAll(/^\s*"([^"]+)",/gm)].map((m) => m[1]);
    expect(roles.length).toBeGreaterThan(5);
    for (const role of roles) expect(SYMBOL_ROLES, role).toContain(role);
    const tiers = read("../../../../../src/hst/core/device_roles.py").split("TIER_ROLES: dict[str, str] = {")[1].split("}")[0];
    const values = [...tiers.matchAll(/:\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(values.length).toBeGreaterThan(5);
    for (const role of values) expect(SYMBOL_ROLES, role).toContain(role);
  });

  it("draw unknown for a role that is an inherited member of the table", () => {
    for (const role of ["constructor", "toString", "__proto__"]) expect(symbolOf(role), role).toBe("unknown");
  });
});
