/**
 * The page context contract on the client: only the focused pane's
 * registrations reach the reader, a page that unmounts takes its registration
 * with it, and a device carries both of its ids when both are known.
 */

import { useState } from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AiContextProvider, deviceSelection, siteSelection, siteUid, useAiContext } from "./context";
import { panes } from "../workspace/layout";
import { useWorkspace, WorkspaceProvider } from "../workspace/WorkspaceContext";
import { PageContextProbe, readPageContext } from "../test/aiContext";

function Registrar({ paneId, uid }: { paneId: string | null; uid: string }) {
  useAiContext(paneId, { selection: [{ kind: "device", uid }] });
  return null;
}

/** One registering page per pane, as the workspace renders them. */
function Panes() {
  const workspace = useWorkspace()!;
  const ids = panes(workspace.state.root).map((pane) => pane.id);
  return (
    <>
      {ids.map((id) => (
        <Registrar key={id} paneId={id} uid={`dev:${id}`} />
      ))}
      <button type="button" onClick={() => workspace.dispatch({ type: "split", id: workspace.state.focus, dir: "row" })}>
        Split
      </button>
      <button type="button" onClick={() => workspace.dispatch({ type: "focus", id: ids[0] })}>
        Focus the first pane
      </button>
    </>
  );
}

describe("page context", () => {
  // the workspace restores its state from the URL (shell/storage.ts)
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("reads only the focused pane's registrations", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/"]}>
        <WorkspaceProvider>
          <AiContextProvider>
            <Panes />
            <PageContextProbe />
          </AiContextProvider>
        </WorkspaceProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(readPageContext().selection).toHaveLength(1));
    const first = readPageContext().route.pane_id as string;
    expect(readPageContext()).toMatchObject({
      version: 1,
      route: { pathname: "/", pane_id: first, pane_view: "trace" },
      selection: [{ kind: "device", uid: `dev:${first}` }],
    });

    // the new pane takes the focus, and only its registration is read
    await user.click(screen.getByRole("button", { name: "Split" }));
    await waitFor(() => expect(readPageContext().route.pane_id).not.toBe(first));
    const second = readPageContext().route.pane_id as string;
    await waitFor(() => expect(readPageContext().selection).toEqual([{ kind: "device", uid: `dev:${second}` }]));

    await user.click(screen.getByRole("button", { name: "Focus the first pane" }));
    await waitFor(() => expect(readPageContext().route.pane_id).toBe(first));
    await waitFor(() => expect(readPageContext().selection).toEqual([{ kind: "device", uid: `dev:${first}` }]));
  });

  it("removes a page's registration when the page unmounts", async () => {
    function Toggle() {
      const [shown, setShown] = useState(true);
      return (
        <>
          {shown && <Registrar paneId={null} uid="dev:fw1" />}
          <button type="button" onClick={() => setShown(false)}>
            Close the page
          </button>
        </>
      );
    }
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/inventory/devices/inv-1"]}>
        <AiContextProvider>
          <Toggle />
          <PageContextProbe />
        </AiContextProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(readPageContext().selection).toEqual([{ kind: "device", uid: "dev:fw1" }]));

    await user.click(screen.getByRole("button", { name: "Close the page" }));
    await waitFor(() => expect(readPageContext().selection).toBeUndefined());
    expect(readPageContext().route).toEqual({ pathname: "/inventory/devices/inv-1" });
  });

  it("reads nothing outside a provider", () => {
    render(
      <MemoryRouter>
        <PageContextProbe />
      </MemoryRouter>,
    );
    expect(readPageContext()).toBeNull();
  });

  it("leaves out a snapshot id the server would reject", async () => {
    function Page() {
      useAiContext(null, {
        snapshot: { id: "current", origin: "page-default" },
        selection: [{ kind: "site", uid: "LON" }],
      });
      return null;
    }
    render(
      <MemoryRouter>
        <AiContextProvider>
          <Page />
          <PageContextProbe />
        </AiContextProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(readPageContext()).toEqual({
        version: 1,
        route: { pathname: "/" },
        selection: [{ kind: "site", uid: "LON" }],
      }),
    );
  });
});

describe("deviceSelection", () => {
  it("carries the inventory id and the graph uid when both are known", () => {
    expect(deviceSelection("inv-1", "dev:fw1", "fw1", "url")).toEqual({
      kind: "device",
      uid: "dev:fw1",
      inventory_id: "inv-1",
      label: "fw1",
      source: "url",
    });
  });

  it("names the inventory device alone until the graph uid is known", () => {
    expect(deviceSelection("inv-1", undefined, undefined, "url")).toEqual({
      kind: "inventory_device",
      uid: "inv-1",
      label: undefined,
      source: "url",
    });
  });
});

describe("siteSelection", () => {
  it("names a site by its graph uid, the slug of its code", () => {
    expect(siteSelection("LON", "London")).toEqual({
      kind: "site",
      uid: "site:lon",
      label: "London",
      source: "selection",
    });
    expect(siteUid(" New York 1 ")).toBe("site:new-york-1");
    expect(siteUid("FRA/2+b")).toBe("site:fra-2-b");
    expect(siteUid("-dc_a.1-")).toBe("site:dc_a.1");
  });
});
