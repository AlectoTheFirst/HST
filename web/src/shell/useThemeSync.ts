/**
 * The theme sync stays mounted in AppShell.
 */

import { useEffect } from "react";
import type { Me } from "../api/types";
import { applyPref, isThemePref, readPref, watchSystem, writePref } from "./theme";

export function useThemeSync(user: Me | null): void {
  useEffect(() => {
    applyPref(readPref());
  }, []);

  useEffect(() => {
    return watchSystem(() => {
      if (readPref() === "system") applyPref("system");
    });
  }, []);

  // The account's stored theme overrides the local one.
  const serverTheme = user?.theme;
  useEffect(() => {
    if (isThemePref(serverTheme) && serverTheme !== readPref()) writePref(serverTheme);
  }, [serverTheme]);
}
