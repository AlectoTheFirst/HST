// @vitest-environment node
//
// The lists of userStorage.ts hold each key that the SPA sources pass to
// localStorage, sessionStorage, readJson or writeJson.
import { describe, it, expect } from "vitest";
// @ts-expect-error -- "fs" has no type declarations in scope here (see layers.test.ts)
import { readFileSync, readdirSync, statSync } from "fs";
// @ts-expect-error -- "url" has no type declarations in scope here (see layers.test.ts)
import { fileURLToPath } from "url";
import { PREFERENCE_KEYS, USER_KEY_PREFIXES, USER_KEYS } from "../userStorage";

const SRC = fileURLToPath(new URL("..", import.meta.url));
/** The modules that take the key as a parameter. */
const WRAPPERS = ["shell/storage.ts", "userStorage.ts"];
/** A storage call, with its first argument in group 1. */
const CALL = /\b(?:readJson|writeJson|(?:local|session)Storage\.(?:getItem|setItem|removeItem))(?:<[^(]*>)?\(\s*([^,)]*)/g;
const OTHER_USE = /\b(?:local|session)Storage\b(?!\.(?:getItem|setItem|removeItem)\()/;

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir) as string[]) {
    const path = `${dir.replace(/\/$/, "")}/${name}`;
    if (statSync(path).isDirectory()) {
      if (name !== "test") walk(path, out);
    } else if (/\.tsx?$/.test(name) && !name.includes(".test.")) {
      out.push(path);
    }
  }
  return out;
}

function code(file: string): string {
  return (readFileSync(file, "utf8") as string)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

/** The string or the template that `const name` holds in `text`. */
function constant(name: string, text: string, exported: boolean): string | undefined {
  const match = new RegExp(`${exported ? "export " : "\\b"}const ${name}\\s*=\\s*(?:"([^"]*)"|\`([^\`]*)\`)`).exec(text);
  return match ? (match[1] ?? match[2]) : undefined;
}

describe("storage keys in the SPA sources", () => {
  const texts = new Map<string, string>();
  for (const file of walk(SRC, [])) {
    const name = file.slice(SRC.length);
    if (!WRAPPERS.includes(name)) texts.set(name, code(file));
  }

  it("reads the whole source tree", () => {
    expect(texts.size).toBeGreaterThan(100);
  });

  it("holds each key in USER_KEYS, USER_KEY_PREFIXES or PREFERENCE_KEYS", () => {
    const keys = new Set<string>();
    const prefixes = new Set<string>();
    const unresolved: string[] = [];
    for (const [name, text] of texts) {
      for (const [, raw] of text.matchAll(CALL)) {
        const arg = raw.trim();
        let value = /^"[^"]*"$/.test(arg) ? arg.slice(1, -1) : undefined;
        if (value === undefined && /^[A-Za-z_$][\w$]*$/.test(arg)) {
          value = constant(arg, text, false);
          for (const other of texts.values()) value ??= constant(arg, other, true);
        }
        if (value === undefined) unresolved.push(`${name}: ${arg}`);
        else if (value.includes("${")) prefixes.add(value.slice(0, value.indexOf("${")));
        else keys.add(value);
      }
    }
    expect(unresolved).toEqual([]);
    expect([...keys].sort()).toEqual([...USER_KEYS, ...PREFERENCE_KEYS].sort());
    expect([...prefixes].sort()).toEqual([...USER_KEY_PREFIXES].sort());
  });

  it("reaches the 2 storages through getItem, setItem and removeItem only", () => {
    const found = [...texts].filter(([, text]) => OTHER_USE.test(text)).map(([name]) => name);
    expect(found).toEqual([]);
  });
});
