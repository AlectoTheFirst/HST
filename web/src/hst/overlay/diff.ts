export type Kind = "same" | "changed" | "removed" | "added";

/** One line pair of a side-by-side comparison; null where one side has no line. */
export interface Pair {
  a: string | null;
  b: string | null;
  kind: Kind;
}

/** Beyond this many line pairs the comparison is by position, not by longest common subsequence. */
export const LCS_LIMIT = 1_000_000;

/** `a` and `b` side by side: equal lines aligned, a removed line beside an added one as changed. */
export function sideBySide(a: string[], b: string[]): Pair[] {
  if (a.length * b.length > LCS_LIMIT) {
    return Array.from({ length: Math.max(a.length, b.length) }, (_, i) => pair(a[i] ?? null, b[i] ?? null));
  }
  const n = a.length;
  const m = b.length;
  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: Pair[] = [];
  let removed: string[] = [];
  let added: string[] = [];
  const flush = () => {
    for (let k = 0; k < Math.max(removed.length, added.length); k++) out.push(pair(removed[k] ?? null, added[k] ?? null));
    removed = [];
    added = [];
  };
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      flush();
      out.push({ a: a[i], b: b[j], kind: "same" });
      i++;
      j++;
    } else if (j >= m || (i < n && lcs[i + 1][j] >= lcs[i][j + 1])) {
      removed.push(a[i++]);
    } else {
      added.push(b[j++]);
    }
  }
  flush();
  return out;
}

function pair(a: string | null, b: string | null): Pair {
  if (a === null) return { a, b, kind: "added" };
  if (b === null) return { a, b, kind: "removed" };
  return { a, b, kind: a === b ? "same" : "changed" };
}

/** For each line of `after`, whether it is new or changed since `before`; all false without a `before`. */
export function changedSince(before: string[] | null, after: string[]): boolean[] {
  if (!before) return after.map(() => false);
  const out: boolean[] = [];
  for (const p of sideBySide(before, after)) if (p.b !== null) out.push(p.kind !== "same");
  return out;
}
