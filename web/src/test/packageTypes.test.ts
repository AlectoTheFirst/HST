// @vitest-environment node
//
// cytoscape-dagre ships its own types and cytoscape-fcose ships none.
import { describe, it, expect } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here (see layers.test.ts)
import { fileURLToPath } from "url";

const read = (name: string) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${name}`, import.meta.url)), "utf8") as string);

describe("Cytoscape type packages", () => {
  it("keeps only the type package that an import uses", () => {
    const pkg = read("package.json");
    expect(pkg.devDependencies["@types/cytoscape-dagre"]).toBeUndefined();
    expect(pkg.devDependencies["@types/cytoscape-fcose"]).toBeDefined();
    const lock = read("package-lock.json");
    expect(lock.packages["node_modules/@types/cytoscape-dagre"]).toBeUndefined();
    expect(lock.packages[""].devDependencies["@types/cytoscape-dagre"]).toBeUndefined();
  });
});
