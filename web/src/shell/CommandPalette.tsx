/**
 * The top bar's search field, opened as a palette: typed text filters the
 * workspace views and the query catalog, and Enter opens the match in the
 * focused pane. Cmd/Ctrl+K opens it from anywhere outside a text field.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { useWorkspace } from "../workspace/WorkspaceContext";
import { type QueryCatalog, viewHasData } from "../api/types";
import { LISTED_VIEWS } from "../workspace/views";
import { hitText, kindPluralLower, kindSingular } from "../search/kinds";
import { KindChips } from "../search/UnifiedSearch";
import { useSearch } from "../search/useSearch";
import { Icon, type IconName } from "./icons";

interface Entry {
  id: string;
  label: string;
  /** More words the entry matches. */
  keywords?: string[];
  /** Where the entry comes from, shown after the label. */
  group: string;
  /** A second line of text: an object's uid. */
  detail?: string;
  icon: IconName;
  run: () => void;
  /** The palette stays open after it runs. */
  keepOpen?: boolean;
}

/** Objects listed in the palette per kind. */
const OBJECT_LIMIT = 5;

const IP_KEY = "find-ip";
const NAME_KEY = "search";

/** An IPv4 or IPv6 address, with or without a prefix length. */
const IPISH = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]*)(\/\d{1,3})?$/i;

/** Mounted only while open (TopBar), so every opening starts empty. */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const { user } = useAuth();
  const workspace = useWorkspace();
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement | null>(null);
  const listId = useId();

  const catalog = useQuery({
    queryKey: ["queries"],
    queryFn: () => api<QueryCatalog>("/queries"),
    enabled: !!user,
  });

  const objects = useSearch({ text, limit: OBJECT_LIMIT, minLength: 2, enabled: !!user });

  useEffect(() => {
    input.current?.focus();
  }, []);

  const entries = useMemo<Entry[]>(() => {
    if (!workspace) return [];
    const q = text.trim();
    const needle = q.toLowerCase();
    const views: Entry[] = LISTED_VIEWS.map((v) => ({
      id: `view:${v.view}`,
      label: v.label,
      group: "View",
      icon: v.icon,
      run: () => v.open(workspace),
    }));
    const shown = views.filter((v) => viewHasData(v.id.slice("view:".length), catalog.data));
    const queries = catalog.data?.queries ?? [];
    const canned: Entry[] = queries.map((c) => ({
      id: `query:${c.key}`,
      label: c.title,
      group: c.section ?? c.group_title ?? c.group,
      keywords: [c.group, ...(c.keywords ?? [])],
      icon: "explore",
      run: () => workspace.openQuery(c.key),
    }));
    const matches = (e: Entry) =>
      !needle ||
      e.label.toLowerCase().includes(needle) ||
      e.group.toLowerCase().includes(needle) ||
      (e.keywords ?? []).some((k) => k.toLowerCase().includes(needle));
    const found = [...shown, ...canned].filter(matches);

    // the live entries: the text as a parameter to the two lookup queries
    const live: Entry[] = [];
    if (q) {
      const ipQuery = queries.find((c) => c.key === IP_KEY);
      const nameQuery = queries.find((c) => c.key === NAME_KEY);
      if (IPISH.test(q) && ipQuery) {
        live.push({
          id: "live:ip",
          label: `${ipQuery.title}: ${q}`,
          group: ipQuery.group,
          icon: "search",
          run: () => workspace.openQuery(ipQuery.key, false, { ip: q.replace(/\/\d+$/, "") }),
        });
      } else if (nameQuery) {
        live.push({
          id: "live:name",
          label: `${nameQuery.title}: ${q}`,
          group: nameQuery.group,
          icon: "search",
          run: () => workspace.openQuery(nameQuery.key, false, { q }),
        });
      }
    }

    // the objects the shared search finds for the same text, by kind
    const answered = !!q && objects.query === q;
    const graph: Entry[] = [];
    for (const group of answered ? objects.visible : []) {
      for (const hit of group.items) {
        const shown = hitText(hit);
        const uid = hit.target?.uid ?? hit.uid;
        graph.push({
          id: `object:${group.id}:${hit.key}`,
          label: shown.name,
          group: kindSingular(hit.kind),
          detail: shown.uid ?? shown.detail,
          icon: "explore",
          run: () => (uid ? workspace.openSearch(q, uid) : workspace.openSearch(q)),
        });
      }
      if (group.nextCursor) {
        graph.push({
          id: `more:${group.id}`,
          label: group.pending ? "Loading" : `Show more ${kindPluralLower(group.id)}`,
          group: "Search",
          icon: "search",
          keepOpen: true,
          run: () => void objects.more(group.id),
        });
      }
    }
    const listed = graph.filter((e) => e.id.startsWith("object:")).length;
    if (answered && objects.total !== null && objects.total > listed) {
      graph.push({
        id: "object:all",
        label: `Open all ${objects.total} in Explore`,
        group: "Search",
        icon: "search",
        run: () => workspace.openSearch(q),
      });
    }
    return [...live, ...found, ...graph];
  }, [workspace, text, catalog.data, objects]);

  function choose(entry: Entry) {
    entry.run();
    if (entry.keepOpen) input.current?.focus();
    else onClose();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(entries.length - 1, c + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(0, c - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const entry = entries[cursor];
      if (entry) choose(entry);
    }
  }

  return (
    <div className="palette-scrim" role="presentation" onPointerDown={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-label="Search"
        // a press inside the dialog must not reach the scrim and close it
        onPointerDown={(e) => e.stopPropagation()}
      >
        <div className="palette-field">
          <Icon name="search" />
          <input
            ref={input}
            role="combobox"
            aria-label="Search views and queries"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={entries[cursor] ? `${listId}-${entries[cursor].id}` : undefined}
            placeholder="Search"
            spellCheck={false}
            autoComplete="off"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setCursor(0);
            }}
            onKeyDown={onKeyDown}
          />
        </div>
        {!!text.trim() && objects.query === text.trim() && (
          <div className="palette-kinds">
            <KindChips search={objects} onPick={() => {
              setCursor(0);
              input.current?.focus();
            }} />
          </div>
        )}
        <ul className="palette-list" role="listbox" id={listId}>
          {entries.length === 0 && (
            <li className="palette-empty">
              {catalog.isLoading ? "Loading" : objects.loading ? "Searching" : "No matches"}
            </li>
          )}
          {entries.map((entry, i) => (
            <li
              key={entry.id}
              id={`${listId}-${entry.id}`}
              role="option"
              aria-selected={i === cursor}
              className={"palette-item" + (i === cursor ? " on" : "")}
              onPointerMove={() => setCursor(i)}
              onClick={() => choose(entry)}
              onKeyDown={onKeyDown}
            >
              <Icon name={entry.icon} />
              <span className="palette-label">
                {entry.label}
                {entry.detail && <span className="palette-detail">{entry.detail}</span>}
              </span>
              <span className="palette-group">{entry.group}</span>
            </li>
          ))}
          {entries.length > 0 && objects.loading && <li className="palette-empty" role="status">Searching</li>}
          {objects.error && <li className="palette-empty">Object search failed: {objects.error}</li>}
        </ul>
      </div>
    </div>
  );
}

/** Cmd/Ctrl+K from anywhere outside a text field opens the palette. */
export function usePaletteShortcut(openPalette: () => void) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== "k") return;
      const target = e.target instanceof Element ? e.target : null;
      if (target?.closest("textarea, [contenteditable]")) return;
      e.preventDefault();
      openPalette();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openPalette]);
}
