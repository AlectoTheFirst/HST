/**
 * The theme picker in the user menu.
 */

import { useState } from "react";
import { api } from "../api/client";
import { readPref, THEME_OPTIONS, writePref, type ThemePref } from "./theme";

export function ThemeSelect() {
  const [pref, setPref] = useState<ThemePref>(readPref);

  function choose(next: ThemePref) {
    setPref(next);
    writePref(next);
    void api("/me", { method: "PATCH", body: { theme: next } }).catch(() => undefined);
  }

  return (
    <label className="themeselect">
      Theme
      <select value={pref} onChange={(e) => choose(e.target.value as ThemePref)}>
        {THEME_OPTIONS.map((o) => (
          <option key={o.pref} value={o.pref}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
