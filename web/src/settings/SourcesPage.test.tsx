import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SourcesPage from "./SourcesPage";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { ME_ADMIN, ME_OPERATOR, SOURCE_TYPES, SOURCE_UNIFI, SOURCES_RESPONSE } from "../test/fixtures";

function renderSources() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <SourcesPage />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function baseRoutes(overrides: Record<string, MockHandler> = {}) {
  return {
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/source-types": () => ({ status: 200, body: SOURCE_TYPES }),
    "GET /api/sources": () => ({ status: 200, body: SOURCES_RESPONSE }),
    ...overrides,
  };
}

describe("SourcesPage: list with secret-set badges", () => {
  it("shows the source name, type, and a badge per secret field", async () => {
    mockApi(baseRoutes());
    renderSources();

    expect(await screen.findByText(SOURCE_UNIFI.name)).toBeInTheDocument();
    expect(screen.getByText(SOURCE_UNIFI.type)).toBeInTheDocument();
    expect(screen.getByText("password: set")).toBeInTheDocument();
    expect(screen.getByText("enabled")).toBeInTheDocument();
  });
});

describe("SourcesPage: unreadable secrets", () => {
  it("renders a row flagged secrets_unreadable with its secret fields unset", async () => {
    const stale = { ...SOURCE_UNIFI, name: "stale-unifi", secrets_unreadable: true, secrets: { password: false } };
    mockApi(
      baseRoutes({
        "GET /api/sources": () => ({ status: 200, body: { sources: [SOURCE_UNIFI, stale] } }),
      }),
    );
    renderSources();

    expect(await screen.findByText(SOURCE_UNIFI.name)).toBeInTheDocument();
    expect(await screen.findByText(stale.name)).toBeInTheDocument();
    expect(screen.getByText("password: not set")).toBeInTheDocument();
  });
});

describe("SourcesPage: add flow", () => {
  it("type picker renders the schema, then POSTs name/type/config", async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    mockApi(
      baseRoutes({
        "POST /api/sources": (req) => {
          posted = req.body;
          return { status: 201, body: { ...SOURCE_UNIFI, name: "new-unifi" } };
        },
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: /add source/i }));
    await user.type(screen.getByLabelText("Name"), "new-unifi");
    await user.selectOptions(screen.getByLabelText("Type"), "unifi");

    // the label of a required field ends in " *"
    await user.type(screen.getByLabelText("Url", { exact: false }), "https://192.168.1.1");
    await user.type(screen.getByLabelText("User", { exact: false }), "admin");
    await user.type(screen.getByLabelText("Password", { exact: false }), "hunter2");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(posted).toEqual({
      name: "new-unifi",
      type: "unifi",
      config: {
        site_code: "home",
        url: "https://192.168.1.1",
        user: "admin",
        password: "hunter2",
        site: "default",
        verify_ssl: false,
      },
    });
  });
});

describe("SourcesPage: edit is a merge PATCH", () => {
  it("omits the untouched password from the PATCH body", async () => {
    const user = userEvent.setup();
    let patched: unknown = null;
    mockApi(
      baseRoutes({
        "PATCH /api/sources/home-unifi": (req) => {
          patched = req.body;
          return { status: 200, body: SOURCE_UNIFI };
        },
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Edit home-unifi" }));
    const site = screen.getByLabelText("Site");
    await user.clear(site);
    await user.type(site, "backup");
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    expect(patched).toEqual({
      config: {
        site_code: "home",
        url: SOURCE_UNIFI.config.url,
        user: SOURCE_UNIFI.config.user,
        site: "backup",
        verify_ssl: false,
      },
    });
  });

  it("keeps the form open with the server's error and the typed value on a 422", async () => {
    const user = userEvent.setup();
    mockApi(
      baseRoutes({
        "PATCH /api/sources/home-unifi": () => ({
          status: 422,
          body: { error: "invalid config: url: not a valid URL" },
        }),
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Edit home-unifi" }));
    const url = screen.getByLabelText("Url", { exact: false }) as HTMLInputElement;
    await user.clear(url);
    await user.type(url, "not-a-url");
    await user.click(screen.getByRole("button", { name: "Save connection" }));

    expect(await screen.findByText("invalid config: url: not a valid URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Url", { exact: false })).toHaveValue("not-a-url");
    expect(screen.getByRole("button", { name: "Save connection" })).toBeInTheDocument();
  });
});

describe("SourcesPage: delete confirm, and a 409 while a run is in flight", () => {
  it("does nothing when the confirm is declined", async () => {
    const user = userEvent.setup();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    let deleteCalled = false;
    mockApi(
      baseRoutes({
        "DELETE /api/sources/home-unifi": () => {
          deleteCalled = true;
          return { status: 200, body: { ok: true } };
        },
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Delete home-unifi" }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(deleteCalled).toBe(false);
    confirmSpy.mockRestore();
  });

  it("surfaces a 409 when the source has a run in flight", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    mockApi(
      baseRoutes({
        "DELETE /api/sources/home-unifi": () => ({
          status: 409,
          body: { error: "home-unifi has a run in flight" },
        }),
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Delete home-unifi" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("home-unifi has a run in flight");
    vi.restoreAllMocks();
  });
});

describe("SourcesPage: probe", () => {
  it("shows {ok, detail} inline", async () => {
    const user = userEvent.setup();
    mockApi(
      baseRoutes({
        "POST /api/sources/home-unifi/test": () => ({
          status: 200,
          body: { ok: true, detail: "UniFi controller v8.0 reachable" },
        }),
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Probe home-unifi" }));

    expect(await screen.findByText("UniFi controller v8.0 reachable")).toBeInTheDocument();
  });

  it("encodes the source name in the path of the probe", async () => {
    const user = userEvent.setup();
    mockApi(
      baseRoutes({
        "GET /api/sources": () => ({ status: 200, body: { sources: [{ ...SOURCE_UNIFI, name: "lab 1" }] } }),
        "POST /api/sources/lab%201/test": () => ({
          status: 200,
          body: { ok: true, detail: "UniFi controller v8.0 reachable" },
        }),
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Probe lab 1" }));

    expect(await screen.findByText("UniFi controller v8.0 reachable")).toBeInTheDocument();
  });

  it("a second probe finishing does not clear the first probe's in-flight state", async () => {
    const user = userEvent.setup();
    const second = { ...SOURCE_UNIFI, name: "office-unifi" };
    let releaseSlow!: () => void;
    const slow = new Promise<void>((resolve) => {
      releaseSlow = resolve;
    });
    mockApi(
      baseRoutes({
        "GET /api/sources": () => ({ status: 200, body: { sources: [SOURCE_UNIFI, second] } }),
        "POST /api/sources/home-unifi/test": async () => {
          await slow;
          return { status: 200, body: { ok: true, detail: "slow probe done" } };
        },
        "POST /api/sources/office-unifi/test": () => ({
          status: 200,
          body: { ok: true, detail: "fast probe done" },
        }),
      }),
    );
    renderSources();

    await user.click(await screen.findByRole("button", { name: "Probe home-unifi" }));
    await user.click(screen.getByRole("button", { name: "Probe office-unifi" }));

    expect(await screen.findByText("fast probe done")).toBeInTheDocument();
    const slowButton = screen.getByRole("button", { name: "Probe home-unifi" });
    expect(slowButton).toBeDisabled();
    expect(slowButton).toHaveTextContent("Probing");

    releaseSlow();
    expect(await screen.findByText("slow probe done")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Probe home-unifi" })).not.toBeDisabled();
  });
});

describe("SourcesPage: role matrix (sources.py: GET/probe operator, POST/PATCH/DELETE admin)", () => {
  it("an operator sees the list and can probe, but not Add source / Edit / Enable-Disable / Delete", async () => {
    mockApi(baseRoutes({ "GET /api/me": () => ({ status: 200, body: ME_OPERATOR }) }));
    renderSources();

    expect(await screen.findByText(SOURCE_UNIFI.name)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Probe home-unifi" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /add source/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit home-unifi" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Disable home-unifi" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete home-unifi" })).not.toBeInTheDocument();
  });

  it("an admin sees every action", async () => {
    mockApi(baseRoutes({ "GET /api/me": () => ({ status: 200, body: ME_ADMIN }) }));
    renderSources();

    expect(await screen.findByText(SOURCE_UNIFI.name)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /add source/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Probe home-unifi" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit home-unifi" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disable home-unifi" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete home-unifi" })).toBeInTheDocument();
  });
});

describe("SourcesPage: the name rule", () => {
  it("states the name rule on the field", async () => {
    mockApi(baseRoutes());
    renderSources();
    await screen.findByText(SOURCE_UNIFI.name);
    await userEvent.click(screen.getByRole("button", { name: /add source/i }));

    const name = (await screen.findByLabelText("Name")) as HTMLInputElement;
    expect(name).toHaveAttribute("pattern", "[a-z0-9\\-]{2,32}");
    expect(name).toHaveAccessibleDescription(/lowercase letters, digits and hyphens/i);

    name.value = "Unifi-Controller";
    expect(name.checkValidity()).toBe(false);
    name.value = "u";
    expect(name.checkValidity()).toBe(false);
    name.value = "unifi-controller";
    expect(name.checkValidity()).toBe(true);
  });
});

describe("SourcesPage: device fleets", () => {
  // Fleet collectors edit targets; controllers show discovered devices.
  const SCHEMA_VYOS = {
    type: "object",
    title: "VyosConfig",
    properties: {
      host: { type: "string", title: "Host", default: "" },
      site_code: { type: "string", title: "Site Code", default: "home" },
    },
  };
  const SOURCE_VYOS = {
    name: "edge",
    type: "vyos",
    kind: "group",
    config: { site_code: "dc1" },
    secrets: { "auth.password": true },
    enabled: true,
    updated_at: null,
  };

  it("offers editable fleet targets and read-only controller discoveries", async () => {
    mockApi(
      baseRoutes({
        "GET /api/source-types": () => ({
          status: 200,
          body: { types: [...SOURCE_TYPES.types, { type: "vyos", kind: "group", schema: SCHEMA_VYOS }] },
        }),
        "GET /api/sources": () => ({
          status: 200,
          body: { sources: [SOURCE_UNIFI, SOURCE_VYOS] },
        }),
        "GET /api/sources/edge/devices": () => ({
          status: 200,
          body: {
            devices: [
              { host: "r1", port: null, enabled: true, overrides: {}, pinned: false, updated_at: null },
            ],
          },
        }),
        "GET /api/sources/home-unifi/effective": () => ({
          body: { devices: [{ host: "controller", device_uids: ["device:ap"], site: "hq", values: {}, origins: {} }] },
        }),
      }),
    );
    renderSources();

    expect(await screen.findByRole("button", { name: "Devices of edge" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Devices of home-unifi" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Devices of edge" }));
    expect(await screen.findByDisplayValue("r1")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Devices of home-unifi" }));
    expect(await screen.findByText("device:ap")).toBeInTheDocument();
  });
});
