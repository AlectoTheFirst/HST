import { useEffect, useState } from "react";
import { applyPref, readPref, watchSystem, writePref, type ThemePref } from "./theme";

const OPTIONS: { pref: ThemePref; label: string }[] = [
  { pref: "light", label: "Light" },
  { pref: "dark", label: "Dark" },
  { pref: "system", label: "Auto" },
];

export function ThemeToggle() {
  const [pref, setPref] = useState<ThemePref>(readPref);

  useEffect(() => {
    applyPref(pref);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (pref !== "system") return;
    return watchSystem(() => applyPref("system"));
  }, [pref]);

  function choose(next: ThemePref) {
    setPref(next);
    writePref(next);
  }

  return (
    <div className="segs theme-toggle" role="group" aria-label="Colour theme">
      {OPTIONS.map((option) => (
        <button
          key={option.pref}
          type="button"
          aria-pressed={pref === option.pref}
          className={pref === option.pref ? "on" : undefined}
          onClick={() => choose(option.pref)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
