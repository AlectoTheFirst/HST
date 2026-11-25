// @vitest-environment node
//
// A guard over the SPA sources: status is stated in words and the design
// tokens' colours, never with a glyph (shell/icons.tsx). The environment and
// the file reads follow flowdesk/strata/layers.test.ts.
import { describe, it, expect } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync, readdirSync, statSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here (see layers.test.ts)
import { fileURLToPath } from "url";

const SRC = fileURLToPath(new URL("..", import.meta.url));
const GLYPH = /[\u{25A0}-\u{27BF}\u{1F000}-\u{1FAFF}]/u;
const LONE_TIMES = />\s*×\s*</;
// The arrows, the bullet, the middle dot and the en dash.
const DECORATION = /[\u{2190}-\u{21FF}\u{2022}\u{00B7}\u{2013}]/u;
const ELLIPSIS = /\u{2026}/u;
// The functions in these files cut a text to a width.
const CUT_TEXT = ["explore/graphElements.ts", "flowdesk/hopStyle.ts"];

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir) as string[]) {
    const path = `${dir.replace(/\/$/, "")}/${name}`;
    if (statSync(path).isDirectory()) {
      if (name !== "test") walk(path, out);
    } else if (/\.(ts|tsx|css)$/.test(name) && !name.includes(".test.")) {
      out.push(path);
    }
  }
  return out;
}

describe("status glyphs in the SPA sources", () => {
  const files = walk(SRC, []);

  function linesWith(pattern: RegExp, skip: string[] = []): string[] {
    const found: string[] = [];
    for (const file of files) {
      if (skip.includes(file.slice(SRC.length))) continue;
      const lines = (readFileSync(file, "utf8") as string).split("\n");
      lines.forEach((line, i) => {
        if (pattern.test(line)) found.push(`${file.slice(SRC.length)}:${i + 1}`);
      });
    }
    return found;
  }

  it("reads the whole source tree", () => {
    expect(files.length).toBeGreaterThan(100);
  });

  it("holds no symbol or emoji character", () => {
    expect(linesWith(GLYPH)).toEqual([]);
  });

  it("holds no arrow, bullet, middle dot or en dash", () => {
    expect(linesWith(DECORATION)).toEqual([]);
  });

  it("holds the ellipsis character only in the functions that cut a text", () => {
    expect(linesWith(ELLIPSIS, CUT_TEXT)).toEqual([]);
  });

  it("holds no JSX text that is only a multiplication sign", () => {
    const found = files.filter((file) => LONE_TIMES.test(readFileSync(file, "utf8") as string));
    expect(found.map((file) => file.slice(SRC.length))).toEqual([]);
  });
});
