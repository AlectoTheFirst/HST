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
  it("does not call the graph query routes", () => {
    const all = files(DIR).filter((f) => !f.endsWith("no-graph-queries.test.ts"));
    expect(all.length).toBeGreaterThan(0);
    for (const f of all) {
      const text = readFileSync(f, "utf8") as string;
      expect(text, f).not.toContain("/api/cypher");
      expect(text, f).not.toContain("/api/queries");
    }
  });
});
