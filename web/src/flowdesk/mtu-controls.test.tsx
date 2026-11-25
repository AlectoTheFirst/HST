import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Composer } from "./Composer";
import { MTU_QUERY_KEY, MtuControls, initialMtuRequest, submittedMtuRequest } from "./MtuControls";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_SNAPSHOTS } from "../test/fixtures";
import type { MtuRequest } from "../api/types";

/** jsdom runs on an opaque origin without window.localStorage. */
function installStorage(): Map<string, string> {
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
  return data;
}

describe("initialMtuRequest", () => {
  beforeEach(() => {
    installStorage();
  });

  it("falls back to inventory when nothing or something malformed is stored", () => {
    expect(initialMtuRequest()).toEqual({ mode: "inventory" });
    window.localStorage.setItem(MTU_QUERY_KEY, JSON.stringify({ mode: "jumbo" }));
    expect(initialMtuRequest()).toEqual({ mode: "inventory" });
    window.localStorage.setItem(MTU_QUERY_KEY, "not json");
    expect(initialMtuRequest()).toEqual({ mode: "inventory" });
  });

  it("keeps only valid persisted fields", () => {
    window.localStorage.setItem(
      MTU_QUERY_KEY,
      JSON.stringify({
        mode: "packet",
        ip_packet_bytes: 1500,
        reply_ip_packet_bytes: 70000,
        ipv4_df: "yes",
        traffic_class: "x".repeat(300),
        extra: true,
      }),
    );
    const request = initialMtuRequest();
    expect(request.mode).toBe("packet");
    expect(request.ip_packet_bytes).toBe(1500);
    expect(request.reply_ip_packet_bytes).toBeUndefined();
    expect(request.ipv4_df).toBeUndefined();
    expect(request.traffic_class).toHaveLength(256);
    expect("extra" in request).toBe(false);
  });
});

describe("submittedMtuRequest", () => {
  const full: MtuRequest = {
    mode: "packet",
    ip_packet_bytes: 1500,
    ipv4_df: true,
    reply_ip_packet_bytes: 1400,
    traffic_class: " gold ",
  };

  it("sends only the mode when off", () => {
    expect(submittedMtuRequest({ ...full, mode: "off" }, false, true)).toEqual({ mode: "off" });
  });

  it("drops sizes for inventory and keeps the trimmed class", () => {
    expect(submittedMtuRequest({ ...full, mode: "inventory" }, false, true)).toEqual({
      mode: "inventory",
      traffic_class: "gold",
    });
  });

  it("never sends IPv4 DF for an IPv6 destination or a hidden reply size", () => {
    expect(submittedMtuRequest(full, true, false)).toEqual({
      mode: "packet",
      ip_packet_bytes: 1500,
      traffic_class: "gold",
    });
    expect(submittedMtuRequest(full, false, true)).toEqual({
      mode: "packet",
      ip_packet_bytes: 1500,
      ipv4_df: true,
      reply_ip_packet_bytes: 1400,
      traffic_class: "gold",
    });
  });

  it("does not send DF for unfragmented mode", () => {
    expect(submittedMtuRequest({ ...full, mode: "unfragmented" }, false, true)).toEqual({
      mode: "unfragmented",
      ip_packet_bytes: 1500,
      reply_ip_packet_bytes: 1400,
      traffic_class: "gold",
    });
  });
});

describe("MtuControls", () => {
  it("shows size fields only for sized modes and hides DF for IPv6", async () => {
    const user = userEvent.setup();
    let value: MtuRequest = { mode: "inventory" };
    const onChange = vi.fn((next: MtuRequest) => {
      value = next;
    });
    const { rerender } = render(<MtuControls value={value} onChange={onChange} />);
    expect(screen.queryByLabelText("IP packet bytes")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Assessment"), "packet");
    expect(value.mode).toBe("packet");
    rerender(<MtuControls value={value} onChange={onChange} />);
    expect(screen.getByLabelText("IP packet bytes")).toBeInTheDocument();
    expect(screen.getByLabelText("IPv4 Don't Fragment")).toBeInTheDocument();

    rerender(<MtuControls value={value} onChange={onChange} ipv6 />);
    expect(screen.queryByLabelText("IPv4 Don't Fragment")).not.toBeInTheDocument();
    expect(screen.getByLabelText("IP packet bytes")).toHaveAttribute("min", "40");
  });

  it("shows the reply size only when the reply trace is enabled", () => {
    const { rerender } = render(
      <MtuControls value={{ mode: "unfragmented", ip_packet_bytes: 1500 }} onChange={() => {}} />,
    );
    expect(screen.queryByLabelText("Reply IP packet bytes")).not.toBeInTheDocument();
    rerender(
      <MtuControls value={{ mode: "unfragmented", ip_packet_bytes: 1500 }} onChange={() => {}} replyEnabled />,
    );
    expect(screen.getByLabelText("Reply IP packet bytes")).toBeInTheDocument();
  });

  it("hides every input when off", () => {
    render(<MtuControls value={{ mode: "off" }} onChange={() => {}} />);
    expect(screen.queryByLabelText("Traffic class")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Assessment")).toHaveValue("off");
  });
});

describe("Composer MTU submission", () => {
  beforeEach(() => {
    installStorage();
    mockApi({ "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }) });
  });

  function renderComposer() {
    const onTrace = vi.fn();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <Composer onTrace={onTrace} tracing={false} />
      </QueryClientProvider>,
    );
    return onTrace;
  }

  it("keeps the reply trace off while advanced options are closed and enables the reply size with it", async () => {
    const user = userEvent.setup();
    const onTrace = renderComposer();
    await screen.findByRole("combobox", { name: "Snapshot" });
    expect(screen.queryByRole("checkbox", { name: /also trace the reply/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(expect.objectContaining({ reply: false }));

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("checkbox", { name: /also trace the reply/i }));
    await user.selectOptions(screen.getByLabelText("Assessment"), "packet");
    await user.type(screen.getByLabelText("IP packet bytes"), "1500");
    await user.type(screen.getByLabelText("Reply IP packet bytes"), "1400");
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(
      expect.objectContaining({ reply: true, mtu: { mode: "packet", ip_packet_bytes: 1500, reply_ip_packet_bytes: 1400 } }),
    );

    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(expect.objectContaining({ reply: false, mtu: { mode: "inventory" } }));
  });

  it("requests the MTU inventory while advanced options are closed, whatever is persisted", async () => {
    window.localStorage.setItem(MTU_QUERY_KEY, JSON.stringify({ mode: "packet", ip_packet_bytes: 9000 }));
    const user = userEvent.setup();
    const onTrace = renderComposer();
    await screen.findByRole("combobox", { name: "Snapshot" });
    expect(screen.queryByLabelText("Assessment")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "Compare" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenCalledWith(expect.objectContaining({ mtu: { mode: "inventory" }, compareWith: undefined }));
  });

  it("submits inventory by default once advanced options are open and persists the request", async () => {
    const user = userEvent.setup();
    const onTrace = renderComposer();
    await screen.findByRole("combobox", { name: "Snapshot" });
    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenCalledWith(expect.objectContaining({ mtu: { mode: "inventory" } }));

    await user.selectOptions(screen.getByLabelText("Assessment"), "unfragmented");
    await user.type(screen.getByLabelText("IP packet bytes"), "1500");
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(
      expect.objectContaining({ mtu: { mode: "unfragmented", ip_packet_bytes: 1500 } }),
    );
    expect(JSON.parse(window.localStorage.getItem(MTU_QUERY_KEY)!)).toMatchObject({
      mode: "unfragmented",
      ip_packet_bytes: 1500,
    });
  });

  it("sends off as an explicit mode and restores a persisted request", async () => {
    window.localStorage.setItem(MTU_QUERY_KEY, JSON.stringify({ mode: "packet", ip_packet_bytes: 9000, ipv4_df: true }));
    const user = userEvent.setup();
    const onTrace = renderComposer();
    await screen.findByRole("combobox", { name: "Snapshot" });
    await user.click(screen.getByRole("button", { name: /advanced options/i }));
    expect(screen.getByLabelText("IP packet bytes")).toHaveValue(9000);
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(
      expect.objectContaining({ mtu: { mode: "packet", ip_packet_bytes: 9000, ipv4_df: true } }),
    );

    await user.selectOptions(screen.getByLabelText("Assessment"), "off");
    await user.click(screen.getByRole("button", { name: /trace/i }));
    expect(onTrace).toHaveBeenLastCalledWith(expect.objectContaining({ mtu: { mode: "off" } }));
  });
});
