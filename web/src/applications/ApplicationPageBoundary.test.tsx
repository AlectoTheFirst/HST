import { lazy, Suspense } from "react";
import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ApplicationPageBoundary } from "./ApplicationPageBoundary";

afterEach(() => vi.restoreAllMocks());

it("keeps the surrounding workspace visible when a page chunk cannot load", async () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  const Page = lazy(() => Promise.reject(new Error("Failed to fetch dynamically imported module")));
  render(<><p>Existing conversation</p><ApplicationPageBoundary>
    <Suspense fallback={<p>Loading</p>}><Page /></Suspense>
  </ApplicationPageBoundary></>);
  expect(await screen.findByRole("region", { name: "Application page error" })).toBeInTheDocument();
  expect(screen.getByText("Existing conversation")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Reload page" })).toBeInTheDocument();
  expect(screen.getByText("Failed to fetch dynamically imported module")).toBeInTheDocument();
});

it("shows render errors and resets when another draft opens", () => {
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  function BrokenPage(): never { throw new Error("Draft render failed"); }
  const view = render(<ApplicationPageBoundary key="g1"><BrokenPage /></ApplicationPageBoundary>);
  expect(screen.getByText("Draft render failed")).toBeInTheDocument();
  view.rerender(<ApplicationPageBoundary key="g2"><p>Another draft</p></ApplicationPageBoundary>);
  expect(screen.getByText("Another draft")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
