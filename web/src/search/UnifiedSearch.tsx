/**
 * The one object search of the app: a field, the kind chips with their counts,
 * and the hits grouped by kind, each kind a page at a time. Each page sets the
 * kinds it asks for, its own local groups, and what opening a hit does.
 *
 * The parts are exported for a page that lays them out itself (Explore's
 * Search tab); UnifiedSearch puts them together. The keyboard: ArrowDown from
 * the field moves into the hits, ArrowUp and ArrowDown, Home and End move
 * through every listed hit across the groups, Enter opens, Escape returns to
 * the field and, from the field, clears it (or does what the page says).
 */

import { useCallback, useId, useState, type KeyboardEvent } from "react";
import { countText, hitText, kindPlural, kindPluralLower, kindSingular } from "./kinds";
import type { Kind, SearchHit } from "./types";
import { useSearch, type LocalGroup, type SearchState } from "./useSearch";
import "./search.css";

export const PLACEHOLDER = "Name, IP, prefix, range, MAC or /regex/";

const ITEM = "[data-search-item]:not([disabled])";

/** Whether opening the hit has anything to open. */
export function canOpen(hit: SearchHit): boolean {
  return !!(hit.target?.uid ?? hit.uid);
}

export interface SearchKeys {
  /** The id the field must carry. */
  inputId: string;
  /** The id the list of hits carries. */
  listId: string;
  focusInput: () => void;
  onInputKeyDown: (e: KeyboardEvent<HTMLInputElement>) => void;
  onItemKeyDown: (e: KeyboardEvent<HTMLElement>) => void;
}

/** The keyboard of a search field and its hits: the field keeps Enter and
 *  Escape, and the arrows move the focus through the hit buttons. */
export function useSearchKeys({ items, onOpen, onEscape }: {
  items: SearchHit[];
  onOpen: (hit: SearchHit) => void;
  onEscape: () => void;
}): SearchKeys {
  const inputId = useId();
  const listId = useId();
  const input = () => document.getElementById(inputId);
  const focusInput = () => input()?.focus();
  const buttons = () => [...(document.getElementById(listId)?.querySelectorAll<HTMLElement>(ITEM) ?? [])];

  const onInputKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const all = buttons();
      if (all.length === 0) return;
      e.preventDefault();
      (e.key === "ArrowDown" ? all[0] : all[all.length - 1]).focus();
    } else if (e.key === "Enter") {
      const first = items.find(canOpen);
      if (!first) return;
      e.preventDefault();
      onOpen(first);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onEscape();
    }
  };

  const onItemKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    const all = buttons();
    const at = all.indexOf(e.currentTarget);
    if (at < 0) return;
    let next: HTMLElement | null | undefined;
    if (e.key === "ArrowDown") next = all[at + 1];
    else if (e.key === "ArrowUp") next = at === 0 ? input() : all[at - 1];
    else if (e.key === "Home") next = all[0];
    else if (e.key === "End") next = all[all.length - 1];
    else if (e.key === "Escape") next = input();
    else return;
    e.preventDefault();
    next?.focus();
  };

  return { inputId, listId, focusInput, onInputKeyDown, onItemKeyDown };
}

/** The kind chips: one per group with hits, with its count; a press narrows
 *  the list to that group and a second press shows every group again. */
export function KindChips({ search, label = "Filter by kind", onPick }: {
  search: SearchState;
  label?: string;
  onPick?: () => void;
}) {
  if (search.chips.length === 0) return null;
  return (
    <div className="us-chips" role="group" aria-label={label}>
      {search.chips.map((chip) => {
        const on = search.narrowed === chip.id;
        return (
          <button
            key={chip.id}
            type="button"
            className={"us-chip" + (on ? " on" : "")}
            aria-pressed={on}
            onClick={() => {
              search.narrow(chip.id);
              onPick?.();
            }}
          >
            {chip.label} <span className="us-count">{chip.count}</span>
          </button>
        );
      })}
    </div>
  );
}

/** One hit: its kind, its name (a side-store row in one line), a second line
 *  and its uid. */
export function HitLine({ hit }: { hit: SearchHit }) {
  const text = hitText(hit);
  return (
    <>
      <span className="us-kind">{kindSingular(hit.kind)}</span>
      <span className="us-name">{text.name}</span>
      {text.detail && <span className="us-detail">{text.detail}</span>}
      {text.uid && text.uid !== text.name && <span className="us-uid">{text.uid}</span>}
    </>
  );
}

/** The hits, grouped by kind, with a Show more button under a kind that has a
 *  next page, and the state of the search: searching, failed or no match. */
export function SearchResults({ search, keys, onOpen, selected, label = "Search results", emptyText, className }: {
  search: SearchState;
  keys: SearchKeys;
  onOpen: (hit: SearchHit) => void;
  /** The uid shown as the open one. */
  selected?: string | null;
  label?: string;
  emptyText?: (query: string) => string;
  className?: string;
}) {
  const empty = search.fresh && !search.error && search.groups.length === 0 && search.query !== null;
  const stopped = search.answer?.side_store?.timed_out ?? [];
  return (
    <>
      {stopped.length > 0 && (
        <p className="us-note">
          {stopped.map((k) => kindPlural(k)).join(", ")} stopped at the time limit
        </p>
      )}
      {search.loading && search.visible.length === 0 && (
        <p className="us-note" aria-live="polite">
          Searching
        </p>
      )}
      {search.error && <p className="us-note us-error">{search.error}</p>}
      {empty && <p className="us-note">{emptyText ? emptyText(search.query!) : `No match for "${search.query}"`}</p>}
      {search.visible.length > 0 && (
        <ul className={"us-results" + (className ? ` ${className}` : "")} aria-label={label} id={keys.listId}>
          {search.visible.map((group) => (
            <li key={group.id} className="us-group">
              <div className="us-grouphead">
                <span>{group.title}</span> <span className="us-count">{countText(group.count, group.countExact)}</span>
              </div>
              <ul className="us-items" aria-label={group.title}>
                {group.items.map((hit) => {
                  const on = !!selected && (hit.target?.uid ?? hit.uid) === selected;
                  return (
                    <li key={hit.key}>
                      <button
                        type="button"
                        data-search-item=""
                        className={"us-hit" + (on ? " on" : "")}
                        aria-current={on ? "true" : undefined}
                        disabled={!canOpen(hit)}
                        title={hit.uid ?? undefined}
                        onClick={() => onOpen(hit)}
                        onKeyDown={keys.onItemKeyDown}
                      >
                        <HitLine hit={hit} />
                      </button>
                    </li>
                  );
                })}
              </ul>
              {group.error && <p className="us-note us-error">{group.error}</p>}
              {group.nextCursor && (
                <button type="button" className="us-more" disabled={group.pending} onClick={() => void search.more(group.id)}>
                  {group.pending ? "Loading" : `Show more ${kindPluralLower(group.id)}`}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

export interface UnifiedSearchProps {
  /** The accessible name of the field. */
  label: string;
  placeholder?: string;
  /** The kinds the server searches; all kinds when absent. */
  defaultKinds?: readonly Kind[];
  /** The page's own hits for the text, listed first. */
  localGroups?: (text: string) => LocalGroup[];
  /** Only the server hits this keeps are listed. */
  accept?: (hit: SearchHit) => boolean;
  /** The page size of each kind. */
  limit?: number;
  onOpen: (hit: SearchHit) => void;
  /** Escape in the field; it clears the field when absent. */
  onEscape?: () => void;
  /** Empties the field after a hit opens. */
  clearOnOpen?: boolean;
  /** The hits float under the field. */
  popover?: boolean;
  emptyText?: (query: string) => string;
  className?: string;
  /** A class for the list of hits beside its own. */
  resultsClassName?: string;
  initialText?: string;
}

export default function UnifiedSearch({
  label,
  placeholder = PLACEHOLDER,
  defaultKinds,
  localGroups,
  accept,
  limit = 10,
  onOpen,
  onEscape,
  clearOnOpen,
  popover,
  emptyText,
  className,
  resultsClassName,
  initialText = "",
}: UnifiedSearchProps) {
  const [text, setText] = useState(initialText);
  const search = useSearch({ text, kinds: defaultKinds, limit, local: localGroups, accept });
  const open = useCallback(
    (hit: SearchHit) => {
      onOpen(hit);
      if (clearOnOpen) setText("");
    },
    [onOpen, clearOnOpen],
  );
  const keys = useSearchKeys({ items: search.items, onOpen: open, onEscape: onEscape ?? (() => setText("")) });
  const shown = text.trim() !== "";
  return (
    <div className={"us" + (popover ? " us-popover" : "") + (className ? ` ${className}` : "")}>
      <input
        id={keys.inputId}
        type="search"
        className="us-input"
        aria-label={label}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={keys.onInputKeyDown}
      />
      {shown && (
        <div className="us-panel">
          <KindChips search={search} onPick={keys.focusInput} />
          <SearchResults search={search} keys={keys} onOpen={open} emptyText={emptyText} className={resultsClassName} />
        </div>
      )}
    </div>
  );
}
