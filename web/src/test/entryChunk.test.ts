// @vitest-environment node
//
// What the entry chunk holds (SF-12): App.tsx loads the settings and
// inventory pages lazily, and theme.css, which main.tsx imports, carries no
// rules of the lazy views. The file reads follow flowdesk/strata/layers.test.ts.
import { describe, it, expect } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync } from "fs";

const read = (path: string): string => readFileSync(new URL(path, import.meta.url), "utf8") as string;

describe("the entry chunk", () => {
  it("imports no settings or inventory page statically", () => {
    const app = read("../App.tsx");
    const statics = [...app.matchAll(/^import [^;]+ from "(\.\/[^"]+)";$/gm)].map((m) => m[1]);
    const pages = statics.filter((p) => /^\.\/(settings|inventory)\/.*Page/.test(p) || p === "./inventory/connections");
    expect(pages).toEqual([]);
    expect(app).toMatch(/lazy\(\(\) => import\("\.\/settings\/RunsPage"\)\)/);
  });

  it("puts the settings and inventory routes behind a Suspense", () => {
    expect(read("../settings/SettingsLayout.tsx")).toMatch(/<Suspense fallback=\{[^}]*\}>\s*<Outlet \/>\s*<\/Suspense>/);
    expect(read("../inventory/InventoryLayout.tsx")).toMatch(/<Suspense fallback=\{[^}]*\}>\s*<Outlet \/>\s*<\/Suspense>/);
  });

  it("keeps the rules of the lazy views out of theme.css", () => {
    const theme = read("../theme.css").replace(/\/\*[\s\S]*?\*\//g, "");
    const selectors = [...theme.matchAll(/([^{}]+)\{/g)].flatMap((m) => m[1].split(",").map((s) => s.trim()));
    const lazy = selectors.filter((s) => /^\.(st-|gv-|graphview|netmap|sdwan-|equinix-|sitemap-|diff-|chgsim)/.test(s));
    expect(lazy).toEqual([]);
  });
});
