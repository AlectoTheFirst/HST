import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi } from "../test/fetchMock";
import { DeviceName, DeviceNamesProvider, DeviceText, uidLabel, withDeviceNames } from "./deviceNames";

const NAMES = { "dev:fdo2335abc": "fw-fra-02", "dev:x:vyos:core1": "core1" };

describe("withDeviceNames", () => {
  it("replaces each known device uid in prose, with the punctuation after it kept", () => {
    expect(withDeviceNames("crosses none of the devices (dev:fdo2335abc, dev:x:vyos:core1).", NAMES)).toBe(
      "crosses none of the devices (fw-fra-02, core1).",
    );
    expect(withDeviceNames("traced via dev:fdo2335abc.", NAMES)).toBe("traced via fw-fra-02.");
  });

  it("keeps an unknown uid and a device uid inside another longer uid", () => {
    expect(withDeviceNames("dev:unknown1 and bgp:dev:fdo2335abc~10.0.0.1:default", NAMES)).toBe(
      "dev:unknown1 and bgp:dev:fdo2335abc~10.0.0.1:default",
    );
  });

  it("names a device's VRF by its name and the device", () => {
    expect(withDeviceNames("table vrf:dev:fdo2335abc:hosting.", NAMES)).toBe("table hosting on fw-fra-02.");
    expect(uidLabel("vrf:dev:x:vyos:core1:default", NAMES)).toBe("default on core1");
  });

  it("names a device's interface by the device and the interface", () => {
    expect(uidLabel("dev:fdo2335abc/if/Ethernet1/1", NAMES)).toBe("fw-fra-02 Ethernet1/1");
    expect(uidLabel("dev:unknown1/if/eth0", NAMES)).toBe("dev:unknown1/if/eth0");
  });
});

describe("DeviceName", () => {
  it("shows the uid outside the provider", () => {
    render(<DeviceName uid="dev:fdo2335abc" />);
    expect(screen.getByText("dev:fdo2335abc")).toBeInTheDocument();
  });

  it("shows the hostname with the uid in the tooltip inside the provider", async () => {
    mockApi({ "GET /api/explore/device-names": () => ({ body: { names: NAMES } }) });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <DeviceNamesProvider>
          <DeviceName uid="dev:fdo2335abc" /> <DeviceText text="on dev:x:vyos:core1" />
        </DeviceNamesProvider>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("fw-fra-02")).toHaveAttribute("title", "dev:fdo2335abc");
    expect(screen.getByText(/on core1/)).toBeInTheDocument();
  });
});
