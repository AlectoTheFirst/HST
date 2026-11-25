/**
 * The state of one search: the debounced query sent to GET /api/explore/search
 * (typed), the answer grouped by kind, the pages each kind has loaded, the kind
 * chip the user narrowed to, and the page's own local groups.
 *
 * An answer without `groups` (an older server) is grouped from its legacy
 * items by label, with the label counts and no cursor.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError } from "../api/client";
import { exploreApi } from "../api/explore";
import { countText, isKind, kindOfLabel, kindPlural } from "./kinds";
import { KINDS, type HitPage, type Kind, type SearchAnswer, type SearchHit } from "./types";
import { useDebounced } from "./useDebounced";

/** Hits the page found in its own data, shown before the server's groups. */
export interface LocalGroup {
  id: string;
  title: string;
  items: SearchHit[];
}

export interface ResultGroup {
  /** The kind, or the id of a local group or of a legacy label. */
  id: string;
  title: string;
  local: boolean;
  items: SearchHit[];
  count: number;
  countExact: boolean;
  nextCursor: string | null;
  /** A next page is being read. */
  pending: boolean;
  /** The next page failed to load. */
  error: string | null;
}

export interface Chip {
  id: string;
  label: string;
  count: string;
}

export interface SearchOptions {
  /** The text as typed; the hook trims and debounces it. */
  text: string;
  /** The kinds the server searches; all kinds when absent. */
  kinds?: readonly Kind[];
  /** The page size of each kind. */
  limit?: number;
  /** The shortest query sent to the server. */
  minLength?: number;
  enabled?: boolean;
  delay?: number;
  /** The page's own groups for the text, computed as it is typed. */
  local?: (text: string) => LocalGroup[];
  /** Only the server hits this keeps are listed; their groups count what they list. */
  accept?: (hit: SearchHit) => boolean;
}

interface Answer {
  key: string;
  q: string;
  answer?: SearchAnswer;
  error?: string;
  pages: Record<string, HitPage>;
  more: Record<string, { pending: boolean; error: string | null }>;
}

export function errorText(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed";
}

/** A local hit, filled in for the fields only the server sets. */
export function localHit(hit: { key: string; uid: string; name: string; kind: string; detail?: string }): SearchHit {
  return {
    kind: hit.kind,
    key: hit.key,
    uid: hit.uid,
    name: hit.name,
    detail: hit.detail ?? "",
    source: "local",
    matched: "text",
    run: null,
    source_run: null,
    target: { kind: hit.kind, uid: hit.uid },
    fields: {},
  };
}

/** The legacy items of an answer as hits, grouped by the kind of their label. */
function legacyPages(answer: SearchAnswer): Record<string, HitPage> {
  const pages: Record<string, HitPage> = {};
  for (const item of answer.items ?? []) {
    const kind = kindOfLabel(item.label);
    (pages[kind] ??= { items: [], next_cursor: null }).items.push({
      kind,
      key: item.uid,
      uid: item.uid,
      name: item.name,
      detail: item.detail,
      source: "graph",
      matched: item.matched === "address" ? "ip" : (item.matched as SearchHit["matched"]),
      run: null,
      source_run: null,
      target: { kind, uid: item.uid },
      fields: {},
    });
  }
  return pages;
}

function pagesOf(answer: SearchAnswer): Record<string, HitPage> {
  if (!answer.groups) return legacyPages(answer);
  const pages: Record<string, HitPage> = {};
  for (const [kind, page] of Object.entries(answer.groups)) if (page) pages[kind] = { items: page.items ?? [], next_cursor: page.next_cursor ?? null };
  return pages;
}

/** The group ids of an answer in order: the kinds in their fixed order, then
 *  the legacy labels that are no kind, in the order they came. */
function groupOrder(answer: SearchAnswer, pages: Record<string, HitPage>): string[] {
  const ids = new Set<string>();
  for (const k of KINDS) if (pages[k] || answer.kinds?.some((c) => c.kind === k && c.count > 0)) ids.add(k);
  for (const id of Object.keys(pages)) ids.add(id);
  return [...ids];
}

export function useSearch({ text, kinds, limit, minLength = 1, enabled = true, delay, local, accept }: SearchOptions) {
  const trimmed = text.trim();
  const debounced = useDebounced(trimmed, delay);
  const kindList = kinds?.join(",") ?? "";
  const active = enabled && debounced.length >= minLength && debounced.length <= 200;
  const key = `${debounced}\u0000${kindList}\u0000${limit ?? ""}`;
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [narrowed, setNarrowed] = useState<{ q: string; id: string } | null>(null);

  useEffect(() => {
    if (!active) return;
    let stale = false;
    const asked = kindList ? (kindList.split(",") as Kind[]) : undefined;
    exploreApi.find({ q: debounced, kinds: asked, limit }).then(
      (found) => {
        if (!stale) setAnswer({ key, q: debounced, answer: found, pages: pagesOf(found), more: {} });
      },
      (err: unknown) => {
        if (!stale) setAnswer({ key, q: debounced, error: errorText(err), pages: {}, more: {} });
      },
    );
    return () => {
      stale = true;
    };
  }, [active, key, debounced, kindList, limit]);

  // the answer to the text on screen; while a new one loads, the last one stays
  const shown = active ? answer : null;
  const fresh = !!shown && shown.key === key;
  const loading = active && !fresh;

  const localGroups = useMemo(() => (local && trimmed ? local(trimmed) : []), [local, trimmed]);

  const groups = useMemo<ResultGroup[]>(() => {
    const out: ResultGroup[] = localGroups
      .filter((g) => g.items.length > 0)
      .map((g) => ({ id: g.id, title: g.title, local: true, items: g.items, count: g.items.length, countExact: true, nextCursor: null, pending: false, error: null }));
    const listed = new Set(localGroups.flatMap((g) => g.items.map((h) => h.uid)).filter(Boolean));
    const found = shown?.answer;
    if (!found) return out;
    for (const id of groupOrder(found, shown.pages)) {
      const page = shown.pages[id] ?? { items: [], next_cursor: null };
      const items = page.items.filter((h) => !(h.uid && listed.has(h.uid)) && (!accept || accept(h)));
      const counted = found.kinds?.find((c) => c.kind === id);
      const legacyCount = found.groups ? undefined : found.labels?.find((l) => kindOfLabel(l.label) === id)?.count;
      const count = accept ? items.length : (counted?.count ?? legacyCount ?? items.length);
      const countExact = accept ? page.next_cursor === null : (counted?.count_exact ?? true);
      if (count === 0 && items.length === 0) continue;
      const more = shown.more[id];
      out.push({
        id,
        title: kindPlural(id),
        local: false,
        items,
        count,
        countExact,
        nextCursor: page.next_cursor,
        pending: more?.pending ?? false,
        error: more?.error ?? null,
      });
    }
    return out;
  }, [localGroups, shown, accept]);

  const narrowId = narrowed && narrowed.q === debounced && groups.some((g) => g.id === narrowed.id) ? narrowed.id : null;
  const visible = useMemo(() => (narrowId ? groups.filter((g) => g.id === narrowId) : groups), [groups, narrowId]);
  const items = useMemo(() => visible.flatMap((g) => g.items), [visible]);
  const chips = useMemo<Chip[]>(
    () => groups.filter((g) => g.count > 0).map((g) => ({ id: g.id, label: g.title, count: countText(g.count, g.countExact) })),
    [groups],
  );

  /** Narrows the groups to one kind; the same kind again shows them all. */
  const narrow = useCallback(
    (id: string) => setNarrowed((n) => (n && n.q === debounced && n.id === id ? null : { q: debounced, id })),
    [debounced],
  );

  /** Reads the next page of one kind and appends it. */
  const more = useCallback(
    async (id: string) => {
      const current = shown;
      const cursor = current?.pages[id]?.next_cursor;
      if (!current?.answer || !cursor || !isKind(id)) return;
      const mark = (state: { pending: boolean; error: string | null }) =>
        setAnswer((a) => (a && a.key === current.key ? { ...a, more: { ...a.more, [id]: state } } : a));
      mark({ pending: true, error: null });
      try {
        const page = await exploreApi.find({
          q: current.q,
          kinds: [id],
          cursor,
          limit,
          snapshot: current.answer.snapshot ?? undefined,
        });
        const next = page.groups?.[id] ?? { items: [], next_cursor: null };
        setAnswer((a) => {
          if (!a || a.key !== current.key) return a;
          const before = a.pages[id] ?? { items: [], next_cursor: null };
          return {
            ...a,
            pages: { ...a.pages, [id]: { items: [...before.items, ...(next.items ?? [])], next_cursor: next.next_cursor ?? null } },
            more: { ...a.more, [id]: { pending: false, error: null } },
          };
        });
      } catch (err) {
        mark({ pending: false, error: errorText(err) });
      }
    },
    [shown, limit],
  );

  return {
    /** The trimmed text as typed. */
    text: trimmed,
    /** The text the server is asked for, once the typing settles. */
    debounced,
    /** The query of the answer listed, or null before one. */
    query: shown?.q ?? null,
    /** Whether the listed answer is the answer to the settled text. */
    fresh,
    loading,
    error: shown?.error ?? null,
    answer: shown?.answer ?? null,
    /** The legacy total over every kind, for an "All N" entry. */
    total: shown?.answer?.total ?? null,
    groups,
    visible,
    items,
    chips,
    narrowed: narrowId,
    narrow,
    more,
  };
}

export type SearchState = ReturnType<typeof useSearch>;
