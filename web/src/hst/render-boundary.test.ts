// @vitest-environment node
// @ts-expect-error -- "fs" has no type declarations in scope
import { readdirSync, readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope
import { fileURLToPath } from "url";
import { describe, it, expect } from "vitest";

const DIR = fileURLToPath(new URL(".", import.meta.url)) as string;

function files(dir: string): string[] {
  return (readdirSync(dir, { withFileTypes: true }) as { name: string; isDirectory(): boolean }[]).flatMap((e) =>
    e.isDirectory() ? files(`${dir}/${e.name}`) : [`${dir}/${e.name}`],
  );
}

describe("web/src/hst", () => {
  it("imports three.js only under render/", () => {
    const outside = files(DIR).filter((f) => !f.includes("/render/") && /\.tsx?$/.test(f));
    expect(outside.length).toBeGreaterThan(0);
    for (const f of outside) {
      expect(readFileSync(f, "utf8") as string, f).not.toMatch(/from\s+["']three(\/|["'])/);
    }
  });
});
