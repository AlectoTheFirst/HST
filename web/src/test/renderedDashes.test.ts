// @vitest-environment node
//
// Guards over the rendered strings of the SPA sources.
import { describe, it, expect } from "vitest";
import * as ts from "typescript";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync, readdirSync, statSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here (see layers.test.ts)
import { fileURLToPath } from "url";

const SRC = fileURLToPath(new URL("..", import.meta.url));
const DASH = "—";
const DOTS = "...";
// The functions in these files cut a text to a width.
const CUT_TEXT = ["ai/chain.ts", "ai/evidence.tsx", "explore/lanes.ts"];
const NAMED = /^(button|th|dt|h[1-6]|option|summary|legend|label)$/;
// A lower-case word. "iBGP" and "vPC" pass.
const LOWER_START = /^[a-z]([a-z ]|$)/;
const END_MARK = /[.?!]$/;

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir) as string[]) {
    const path = `${dir.replace(/\/$/, "")}/${name}`;
    if (statSync(path).isDirectory()) {
      if (name !== "test") walk(path, out);
    } else if (/\.tsx?$/.test(name) && !name.includes(".test.") && !name.endsWith(".d.ts")) {
      out.push(path);
    }
  }
  return out;
}

interface Text {
  file: string;
  line: number;
  text: string;
  jsx: boolean;
}

interface Scan {
  files: number;
  strings: Text[];
  /** The first and the last text of each element that `NAMED` matches. */
  starts: Text[];
  ends: Text[];
}

let scanned: Scan | null = null;

function scan(): Scan {
  if (scanned) return scanned;
  const files = walk(SRC, []);
  const out: Scan = { files: files.length, strings: [], starts: [], ends: [] };
  for (const path of files) {
    const file = path.slice(SRC.length);
    const source = ts.createSourceFile(
      path,
      readFileSync(path, "utf8") as string,
      ts.ScriptTarget.Latest,
      true,
      path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
    );
    const at = (node: ts.Node, text: string, jsx: boolean): Text => ({
      file,
      line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
      text,
      jsx,
    });
    const visit = (node: ts.Node) => {
      if (
        ts.isStringLiteral(node) ||
        ts.isNoSubstitutionTemplateLiteral(node) ||
        ts.isTemplateHead(node) ||
        ts.isTemplateMiddle(node) ||
        ts.isTemplateTail(node) ||
        ts.isJsxText(node)
      ) {
        out.strings.push(at(node, node.text, ts.isJsxText(node)));
      }
      if (ts.isJsxElement(node) && NAMED.test(node.openingElement.tagName.getText(source))) {
        const children = node.children.filter((child) => !(ts.isJsxText(child) && child.text.trim() === ""));
        const first = children[0];
        const last = children[children.length - 1];
        if (first && ts.isJsxText(first)) out.starts.push(at(first, first.text.trim(), true));
        if (last && ts.isJsxText(last)) out.ends.push(at(last, last.text.trim(), true));
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  scanned = out;
  return out;
}

const where = (found: Text[]) => found.map(({ file, line }) => `${file}:${line}`);

describe("em dashes in rendered SPA text", () => {
  it(
    "holds none outside the bare placeholder",
    () => {
      const { files, strings } = scan();
      const found = strings.filter(({ text, jsx }) => {
        const bare = text === DASH || (jsx && text.trim() === DASH);
        return text.includes(DASH) && !bare;
      });
      expect(files).toBeGreaterThan(100);
      expect(strings.length).toBeGreaterThan(1000);
      expect(where(found)).toEqual([]);
    },
    60_000,
  );
});

describe("three full stops in rendered SPA text", () => {
  it(
    "holds them only in the functions that cut a text",
    () => {
      const found = scan().strings.filter(({ file, text }) => text.includes(DOTS) && !CUT_TEXT.includes(file));
      expect(where(found)).toEqual([]);
    },
    60_000,
  );
});

describe("the text of a button, head, term, option, summary, legend and label", () => {
  it(
    "starts with a capital letter",
    () => {
      const { starts } = scan();
      expect(starts.length).toBeGreaterThan(500);
      expect(where(starts.filter(({ text }) => LOWER_START.test(text)))).toEqual([]);
    },
    60_000,
  );

  it(
    "ends with no full stop, question mark or exclamation mark",
    () => {
      const { ends } = scan();
      expect(ends.length).toBeGreaterThan(500);
      expect(where(ends.filter(({ text }) => END_MARK.test(text)))).toEqual([]);
    },
    60_000,
  );
});
