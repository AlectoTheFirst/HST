/**
 * The line icons of the shell chrome.
 */

export type IconName =
  | "trace"
  | "explore"
  | "network"
  | "sdwan"
  | "equinix"
  | "diff"
  | "changesim"
  | "assessments"
  | "applications"
  | "analysis"
  | "search"
  | "collapse"
  | "expand"
  | "split-row"
  | "split-col"
  | "close"
  | "chevron-down"
  | "chevron-right"
  | "arrow-right"
  | "settings";

const PATHS: Record<IconName, string> = {
  trace: "M5 18a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm14-8a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM7 16h4a4 4 0 0 0 4-4 4 4 0 0 1 2-3.5",
  explore: "M11 17a6 6 0 1 0 0-12 6 6 0 0 0 0 12Zm9 3-4.5-4.5",
  // a diagram: one box on top, cabled down to two boxes
  network: "M9 3h6v4H9zM3 17h6v4H3zm12 0h6v4h-6zM12 7v5M6 17v-5h12v5",
  // an edge at the bottom with two tunnels up to two hubs
  sdwan: "M12 21a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM6 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm12 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM11 17.3 6.8 6.8m6.2 10.5 4.2-10.5",
  // two ports at the bottom, cabled up to one switch, and a circuit across
  equinix: "M8 4h8v4H8zM5 16h4v4H5zm10 0h4v4h-4zM12 8v3m-5 5v-2h10v2M9 18h6",
  diff: "M4 8h13m-4-4 4 4-4 4M20 16H7m4-4-4 4 4 4",
  changesim: "M9 3h6m-5 0v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3",
  assessments:
    "M9 4h6v3H9zm0 1H7a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2m-6 7h6m-6 4h4",
  // four tiles
  applications: "M4 4h7v7H4zm9 0h7v7h-7zM4 13h7v7H4zm9 0h7v7h-7z",
  // three bars over a base line
  analysis: "M4 20h16M7 17v-5m5 5V7m5 10v-8",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14Zm9 2-3.5-3.5",
  collapse: "m11 17-5-5 5-5m7 10-5-5 5-5",
  expand: "m13 7 5 5-5 5M6 7l5 5-5 5",
  "split-row": "M4 5h16v14H4zm8 0v14",
  "split-col": "M4 5h16v14H4zm0 7h16",
  close: "M6 6l12 12M18 6 6 18",
  "chevron-down": "m6 9 6 6 6-6",
  "chevron-right": "m9 6 6 6-6 6",
  "arrow-right": "M4 12h16m-6-6 6 6-6 6",
  settings:
    "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5v.2a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1h.2a2 2 0 1 1 0 4H21a1.6 1.6 0 0 0-1.5 1Z",
};

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      viewBox="0 0 24 24"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
    >
      <path
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        d={PATHS[name]}
      />
    </svg>
  );
}

/** The wordmark's mark: three strata in a rounded tile, in the accent. */
export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 24 24" width="26" height="26" aria-hidden="true">
      <rect width="24" height="24" rx="6" fill="var(--accent)" />
      <path
        d="M6 8.5h12M6 12h9M6 15.5h6"
        fill="none"
        stroke="#fff"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}
