import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DevicesPanel } from "./DevicesPanel";
import { mockApi, type MockHandler } from "../test/fetchMock";
import type { SourceDevice } from "../api/types";

const R1: SourceDevice = {
  host: "r1",
  port: null,
  enabled: true,
  updated_at: "2026-08-27T08:00:00+00:00",
};

const R2: SourceDevice = {
  host: "r2",
  port: 2222,
  enabled: false,
  updated_at: null,
};

function renderPanel(canManage = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <DevicesPanel sourceName="edge" canManage={canManage} />
    </QueryClientProvider>,
  );
}

function routes(overrides: Record<string, MockHandler> = {}) {
  return {
    "GET /api/sources/edge/devices": () => ({ status: 200, body: { devices: [R1, R2] } }),
    ...overrides,
  };
}

describe("DevicesPanel: list", () => {
  it("renders the fleet with its ports", async () => {
    mockApi(routes());
    renderPanel();

    expect(await screen.findByDisplayValue("r1")).toBeInTheDocument();
    expect(screen.getByDisplayValue("r2")).toBeInTheDocument();
    expect(screen.getByDisplayValue("2222")).toBeInTheDocument();
  });

  it("offers only the host and port fields", async () => {
    mockApi(routes());
    renderPanel();

    await screen.findByDisplayValue("r1");
    expect(screen.queryByLabelText(/overrides/i)).not.toBeInTheDocument();
    expect(screen.getAllByLabelText("Host")).toHaveLength(2);
    expect(screen.getAllByLabelText("Port")).toHaveLength(2);
  });

  it("hides the editing controls from an operator", async () => {
    mockApi(routes());
    renderPanel(false);

    expect(await screen.findByDisplayValue("r1")).toBeDisabled();
    expect(screen.queryByRole("button", { name: /save devices/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add device/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Probe r1" })).toBeInTheDocument();
  });
});

describe("DevicesPanel: save", () => {
  it("PUTs the whole draft on save", async () => {
    const user = userEvent.setup();
    let put: unknown = null;
    mockApi(
      routes({
        "PUT /api/sources/edge/devices": (req) => {
          put = req.body;
          return { status: 200, body: { devices: [R1, R2] } };
        },
      }),
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /add device/i }));
    const hostInputs = screen.getAllByLabelText("Host");
    await user.type(hostInputs[hostInputs.length - 1], "r3");
    await user.click(screen.getByRole("button", { name: /save devices/i }));

    expect(put).toEqual({
      devices: [
        { host: "r1", port: null, enabled: true },
        { host: "r2", port: 2222, enabled: false },
        { host: "r3", port: null, enabled: true },
      ],
    });
  });

  it("keeps the draft and shows the server message on a 422", async () => {
    const user = userEvent.setup();
    mockApi(
      routes({
        "PUT /api/sources/edge/devices": () => ({
          status: 422,
          body: { error: "r9: host must be reachable" },
        }),
      }),
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /add device/i }));
    const hosts = screen.getAllByLabelText("Host");
    await user.type(hosts[hosts.length - 1], "r9");
    await user.click(screen.getByRole("button", { name: /save devices/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("host must be reachable");
    expect(screen.getByDisplayValue("r9")).toBeInTheDocument();
  });
});

describe("DevicesPanel: probe", () => {
  it("posts the per-device test and renders its detail", async () => {
    const user = userEvent.setup();
    mockApi(
      routes({
        "POST /api/sources/edge/devices/r1/test": () => ({
          status: 200,
          body: { ok: true, detail: "VyOS 1.5" },
        }),
      }),
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Probe r1" }));
    expect(await screen.findByText("VyOS 1.5")).toBeInTheDocument();
  });

  it("encodes the host in the path of the per-device test", async () => {
    const user = userEvent.setup();
    mockApi({
      "GET /api/sources/edge/devices": () => ({ status: 200, body: { devices: [{ ...R1, host: "fe80::1%eth0" }] } }),
      "POST /api/sources/edge/devices/fe80%3A%3A1%25eth0/test": () => ({
        status: 200,
        body: { ok: true, detail: "VyOS 1.5" },
      }),
    });
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Probe fe80::1%eth0" }));
    expect(await screen.findByText("VyOS 1.5")).toBeInTheDocument();
  });

  it("disables probing while the draft is unsaved", async () => {
    const user = userEvent.setup();
    mockApi(routes());
    renderPanel();

    const host = (await screen.findAllByLabelText("Host"))[0];
    await user.type(host, "x");
    expect(screen.getByRole("button", { name: "Probe r1x" })).toBeDisabled();
  });
});
