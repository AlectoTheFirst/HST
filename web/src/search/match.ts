/**
 * The query grammar of the server search (GET /api/explore/search), for the
 * filters that run in the page: the estate tree and the twin's own find.
 *
 * The mode follows from the text: /.../ is a regular expression, then an IPv4
 * or IPv6 address, a prefix (a.b.c.d/n or v6/n), a range "a-b" of two
 * addresses of one family with a <= b, a MAC address (aa:bb:cc:dd:ee:ff,
 * aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff or aabbccddeeff), else text. Text is case
 * insensitive and every word of it must be in the label or the uid.
 */

export type QueryMode = "regex" | "ip" | "prefix" | "range" | "mac" | "text";

interface Net {
  v: 4 | 6;
  net: bigint;
  len: number;
}

export interface ParsedQuery {
  mode: QueryMode;
  /** The trimmed text the query was parsed from. */
  text: string;
  test(candidates: readonly string[]): boolean;
}

/** The longest regular expression the server compiles. */
export const REGEX_MAX = 128;

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/i;

function parseV4(text: string): bigint | null {
  const m = V4.exec(text);
  if (!m) return null;
  let out = 0n;
  for (const part of m.slice(1)) {
    const n = Number(part);
    if (n > 255) return null;
    out = (out << 8n) | BigInt(n);
  }
  return out;
}

function parseV6(text: string): bigint | null {
  if (!text.includes(":")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    const pieces = part.split(":");
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i];
      if (i === pieces.length - 1 && piece.includes(".")) {
        const v4 = parseV4(piece);
        if (v4 === null) return null;
        out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else if (HEX_GROUP.test(piece)) {
        out.push(parseInt(piece, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  let all: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    all = [...head, ...new Array<number>(fill).fill(0), ...tail];
  } else {
    all = head;
  }
  if (all.length !== 8) return null;
  return all.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function parseAddress(text: string): Net | null {
  const v4 = parseV4(text);
  if (v4 !== null) return { v: 4, net: v4, len: 32 };
  const v6 = parseV6(text);
  if (v6 !== null) return { v: 6, net: v6, len: 128 };
  return null;
}

const bits = (v: 4 | 6) => (v === 4 ? 32 : 128);

function masked(addr: bigint, v: 4 | 6, len: number): bigint {
  const width = BigInt(bits(v));
  const host = width - BigInt(len);
  return (addr >> host) << host;
}

function parsePrefix(text: string): Net | null {
  const slash = text.lastIndexOf("/");
  if (slash < 0) return null;
  const addr = parseAddress(text.slice(0, slash));
  const lenText = text.slice(slash + 1);
  if (!addr || !/^\d{1,3}$/.test(lenText)) return null;
  const len = Number(lenText);
  if (len > bits(addr.v)) return null;
  return { v: addr.v, net: masked(addr.net, addr.v, len), len };
}

function parseRange(text: string): [Net, Net] | null {
  const m = /^(\S+)\s*-\s*(\S+)$/.exec(text);
  if (!m) return null;
  const a = parseAddress(m[1]);
  const b = parseAddress(m[2]);
  if (!a || !b || a.v !== b.v || a.net > b.net) return null;
  return [a, b];
}

const MAC_SHAPES = [/^[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$/i, /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i, /^[0-9a-f]{12}$/i];
const MAC_IN_TEXT = /(?<![0-9a-f])(?:[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})(?![0-9a-f])/gi;

const hexOf = (mac: string) => mac.replace(/[^0-9a-f]/gi, "").toLowerCase();

/** The inner text of /.../, or null when the text is not one. */
function regexBody(text: string): string | null {
  return text.length >= 3 && text.startsWith("/") && text.endsWith("/") ? text.slice(1, -1) : null;
}

/** Whether the server's guard would refuse the pattern: too long, or a back
 *  reference or a lookaround. */
export function regexRefused(pattern: string): boolean {
  return pattern.length > REGEX_MAX || /\\[1-9]|\\k<|\(\?<?[=!]/.test(pattern);
}

/** The mode the server reads the text in. */
export function detectMode(text: string): QueryMode {
  const t = text.trim();
  if (regexBody(t) !== null) return "regex";
  if (parseAddress(t)) return "ip";
  if (parsePrefix(t)) return "prefix";
  if (parseRange(t)) return "range";
  if (MAC_SHAPES.some((re) => re.test(t))) return "mac";
  return "text";
}

/** The addresses and prefixes a candidate holds: the whole string, each word,
 *  and a uid's address after its namespace ("ip:blue/10.1.2.7"). */
function netsOf(candidate: string): Net[] {
  const out: Net[] = [];
  const words = candidate.trim().split(/[\s,]+/).filter(Boolean);
  for (const word of words) {
    for (const piece of new Set([word, word.replace(/^[A-Za-z_]+:[^/\s]*\//, "")])) {
      const net = parseAddress(piece) ?? parsePrefix(piece);
      if (net) out.push(net);
    }
  }
  return out;
}

const NONE: ParsedQuery = { mode: "text", text: "", test: () => true };

/** Parses the text once, for many candidates. Empty text matches everything. */
export function parseQuery(text: string): ParsedQuery {
  const t = text.trim();
  if (!t) return NONE;
  const mode = detectMode(t);
  const nets = (candidates: readonly string[]) => candidates.flatMap(netsOf);
  switch (mode) {
    case "regex": {
      const body = regexBody(t)!;
      let re: RegExp | null = null;
      if (!regexRefused(body)) {
        try {
          re = new RegExp(`^(?:${body})$`, "i");
        } catch {
          re = null;
        }
      }
      return { mode, text: t, test: (cs) => re !== null && cs.some((c) => re.test(c)) };
    }
    case "ip": {
      const addr = parseAddress(t)!;
      return { mode, text: t, test: (cs) => nets(cs).some((n) => n.v === addr.v && n.len === addr.len && n.net === addr.net) };
    }
    case "prefix": {
      const p = parsePrefix(t)!;
      return {
        mode,
        text: t,
        test: (cs) =>
          nets(cs).some(
            (n) => n.v === p.v && (n.len === bits(n.v) ? masked(n.net, n.v, p.len) === p.net : n.len === p.len && n.net === p.net),
          ),
      };
    }
    case "range": {
      const [a, b] = parseRange(t)!;
      return {
        mode,
        text: t,
        test: (cs) => nets(cs).some((n) => n.v === a.v && n.len === bits(n.v) && n.net >= a.net && n.net <= b.net),
      };
    }
    case "mac": {
      const hex = hexOf(t);
      return { mode, text: t, test: (cs) => cs.some((c) => (c.match(MAC_IN_TEXT) ?? []).some((m) => hexOf(m) === hex)) };
    }
    default: {
      const words = t.toLowerCase().split(/\s+/);
      return {
        mode,
        text: t,
        test: (cs) => {
          const lower = cs.map((c) => c.toLowerCase());
          return words.every((w) => lower.some((c) => c.includes(w)));
        },
      };
    }
  }
}

type Candidate = string | readonly (string | null | undefined)[];

const listOf = (candidate: Candidate): string[] =>
  (typeof candidate === "string" ? [candidate] : candidate).filter((c): c is string => typeof c === "string" && c !== "");

/** Whether the candidate (a string, or the strings of one object such as its
 *  label and its uid) matches the query. Empty text matches everything. */
export function matches(query: string | ParsedQuery, candidate: Candidate): boolean {
  const q = typeof query === "string" ? parseQuery(query) : query;
  return q.text === "" || q.test(listOf(candidate));
}

/** The order of a match: 0 when the label or the uid is the query, 1 when the
 *  label starts with it, 2 when the label holds it, 3 for any other match;
 *  -1 for no match. Address, MAC and regex matches rank 0 when equal, else 2. */
export function rank(query: string | ParsedQuery, label: string, uid?: string | null): number {
  const q = typeof query === "string" ? parseQuery(query) : query;
  if (q.text === "" || !q.test(listOf([label, uid]))) return -1;
  const needle = q.text.toLowerCase().replace(/\s+/g, " ");
  const l = label.toLowerCase();
  const u = (uid ?? "").toLowerCase();
  if (l === needle || u === needle) return 0;
  if (q.mode !== "text") return 2;
  if (l.startsWith(needle)) return 1;
  if (l.includes(needle)) return 2;
  return 3;
}
