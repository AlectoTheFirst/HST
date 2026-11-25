import { lazy, Suspense } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RootErrorBoundary } from "./RootErrorBoundary";

function Broken(): never {
  throw new Error("render failed");
}

const MissingChunk = lazy(() => Promise.reject(new Error("Failed to fetch dynamically imported module")));

beforeEach(() => {
  // React logs each caught error.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RootErrorBoundary", () => {
  it("renders its children", () => {
    render(
      <RootErrorBoundary>
        <p>content</p>
      </RootErrorBoundary>,
    );
    expect(screen.getByText("content")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows the error of a failed render with a reload button", async () => {
    const reload = vi.fn();
    vi.stubGlobal("location", { ...window.location, reload });
    render(
      <RootErrorBoundary>
        <Broken />
      </RootErrorBoundary>,
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Page not displayed");
    expect(alert).toHaveTextContent("render failed");
    await userEvent.setup().click(screen.getByRole("button", { name: "Reload" }));
    expect(reload).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("shows the error of a lazy chunk that failed to load", async () => {
    render(
      <RootErrorBoundary>
        <Suspense fallback={null}>
          <MissingChunk />
        </Suspense>
      </RootErrorBoundary>,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Failed to fetch dynamically imported module");
  });
});
