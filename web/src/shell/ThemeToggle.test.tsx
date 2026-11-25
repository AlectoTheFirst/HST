import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeToggle } from "./ThemeToggle";
import { THEME_KEY, readPref, resolve } from "./theme";

/**
 * This suite's jsdom runs on an opaque origin, where `window.localStorage` is
 * undefined.
 */
function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
}

describe("ThemeToggle", () => {
  beforeEach(() => {
    installStorage();
    delete document.documentElement.dataset.theme;
  });

  it("defaults to Auto when nothing is stored", () => {
    render(<ThemeToggle />);
    expect(screen.getByRole("button", { name: "Auto" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Light" })).toHaveAttribute("aria-pressed", "false");
  });

  it("stamps the chosen palette on <html> and persists it", async () => {
    const user = userEvent.setup();
    render(<ThemeToggle />);

    await user.click(screen.getByRole("button", { name: "Light" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(window.localStorage.getItem(THEME_KEY)).toBe("light");

    await user.click(screen.getByRole("button", { name: "Dark" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(window.localStorage.getItem(THEME_KEY)).toBe("dark");
  });

  it("restores the stored preference on mount", () => {
    window.localStorage.setItem(THEME_KEY, "dark");
    render(<ThemeToggle />);
    expect(screen.getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "true");
  });

  it("applies the stored preference to <html> on mount", () => {
    document.documentElement.dataset.theme = "light";
    window.localStorage.setItem(THEME_KEY, "dark");
    render(<ThemeToggle />);
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("falls back to Auto on an unrecognised stored value", () => {
    window.localStorage.setItem(THEME_KEY, "chartreuse");
    expect(readPref()).toBe("system");
  });

  it("survives storage being unavailable", async () => {
    Object.defineProperty(window, "localStorage", { configurable: true, value: undefined });
    const user = userEvent.setup();
    expect(readPref()).toBe("system");
    render(<ThemeToggle />);
    await user.click(screen.getByRole("button", { name: "Dark" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("resolves an explicit preference without consulting the OS", () => {
    // jsdom's matchMedia reports no dark preference.
    expect(resolve("dark")).toBe("dark");
    expect(resolve("light")).toBe("light");
    expect(resolve("system")).toBe("light");
  });
});
