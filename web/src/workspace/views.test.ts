// @vitest-environment node
//
// The view registry against the server's list of pane views: a view the
// server does not know fails validation of every AI request from that pane.
// The file reads follow flowdesk/strata/layers.test.ts.
import { describe, it, expect } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here (see layers.test.ts)
import { fileURLToPath } from "url";
import { VIEWS, VIEW_IDS, VIEW_LABEL, isPaneView } from "./views";

const RESOLVER = fileURLToPath(new URL("../../../src/hst/app/ai/context_resolver.py", import.meta.url));

describe("the workspace view registry", () => {
  it("holds the pane views the server accepts, and no other", () => {
    const text = readFileSync(RESOLVER, "utf8") as string;
    const block = /PaneView = Literal\[([^\]]*)\]/.exec(text)?.[1] ?? "";
    const server = [...block.matchAll(/"([a-z]+)"/g)].map((m) => m[1]).sort();
    expect(server.length).toBeGreaterThan(5);
    expect([...VIEW_IDS].sort()).toEqual(server);
  });

  it("gives every view one record with a label and an icon", () => {
    expect(VIEWS.map((v) => v.view)).toEqual([...VIEW_IDS]);
    for (const v of VIEWS) expect(VIEW_LABEL[v.view]).toBe(v.label);
    expect(isPaneView("sdwan")).toBe(true);
    expect(isPaneView("nope")).toBe(false);
  });
});
