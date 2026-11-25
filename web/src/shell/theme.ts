/**
 * The theme preference "system" follows the OS.
 */

export type ThemePref =
  | "light"
  | "dark"
  | "system"
  | "dracula"
  | "catppuccin"
  | "tokyo-night"
  | "nord";

export const THEME_KEY = "hst-theme";

const PREFS: readonly ThemePref[] = [
  "light",
  "dark",
  "system",
  "dracula",
  "catppuccin",
  "tokyo-night",
  "nord",
];

/** Picker order and display names; the value set must match the backend's
 *  THEMES allowlist (app/auth.py) and theme.css's palette blocks. */
export const THEME_OPTIONS: readonly { pref: ThemePref; label: string }[] = [
  { pref: "system", label: "Auto" },
  { pref: "light", label: "Light" },
  { pref: "dark", label: "Dark" },
  { pref: "dracula", label: "Dracula" },
  { pref: "catppuccin", label: "Catppuccin Mocha" },
  { pref: "tokyo-night", label: "Tokyo Night" },
  { pref: "nord", label: "Nord" },
];

/** Type guard for values arriving from storage or the API. */
export function isThemePref(value: unknown): value is ThemePref {
  return typeof value === "string" && PREFS.includes(value as ThemePref);
}

/** The stored preference, or "system" when unset or unrecognised. */
export function readPref(): ThemePref {
  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(THEME_KEY);
  } catch {
    // storage unavailable
    return "system";
  }
  return PREFS.includes(stored as ThemePref) ? (stored as ThemePref) : "system";
}

/** True when the OS asks for a dark palette. */
function systemPrefersDark(): boolean {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

export function resolve(pref: ThemePref): Exclude<ThemePref, "system"> {
  if (pref === "system") return systemPrefersDark() ? "dark" : "light";
  return pref;
}

/** Stamp the resolved palette on <html> so theme.css can select on it. */
export function applyPref(pref: ThemePref): void {
  document.documentElement.dataset.theme = resolve(pref);
}

/** Persist and apply in one step. Storage failures still apply the theme. */
export function writePref(pref: ThemePref): void {
  try {
    window.localStorage.setItem(THEME_KEY, pref);
  } catch {
    // storage unavailable
  }
  applyPref(pref);
}

/** Calls `onChange` when the OS palette changes. */
export function watchSystem(onChange: () => void): () => void {
  const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
  if (!mq) return () => {};
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}
