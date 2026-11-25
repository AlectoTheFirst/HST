import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeSelect } from "./ThemeSelect";
import { THEME_KEY } from "./theme";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", () => ({ api: apiMock }));

/** Same opaque-origin stand-in as ThemeToggle.test.tsx. */
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

describe("ThemeSelect", () => {
  beforeEach(() => {
    installStorage();
    delete document.documentElement.dataset.theme;
    apiMock.mockReset();
    apiMock.mockResolvedValue({});
  });

  it("offers every palette and defaults to Auto", () => {
    render(<ThemeSelect />);
    const select = screen.getByRole("combobox", { name: "Theme" });
    expect(select).toHaveValue("system");
    for (const label of ["Dracula", "Catppuccin Mocha", "Tokyo Night", "Nord"]) {
      expect(screen.getByRole("option", { name: label })).toBeInTheDocument();
    }
  });

  it("applies a named palette locally and persists it to the account", async () => {
    const user = userEvent.setup();
    render(<ThemeSelect />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Theme" }), "dracula");
    expect(document.documentElement.dataset.theme).toBe("dracula");
    expect(window.localStorage.getItem(THEME_KEY)).toBe("dracula");
    expect(apiMock).toHaveBeenCalledWith("/me", { method: "PATCH", body: { theme: "dracula" } });
  });

  it("keeps the palette applied even when the account write fails", async () => {
    apiMock.mockRejectedValue(new Error("offline"));
    const user = userEvent.setup();
    render(<ThemeSelect />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Theme" }), "nord");
    expect(document.documentElement.dataset.theme).toBe("nord");
  });
});
