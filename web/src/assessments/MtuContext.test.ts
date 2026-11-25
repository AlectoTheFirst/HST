import { describe, expect, it } from "vitest";
import { traceDraft } from "./context";
import type { TraceParams } from "../flowdesk/Composer";

describe("MTU contextual assessment", () => {
  it("copies submitted packet semantics independently of the live trace form", () => {
    const input: TraceParams & { reply: boolean } = { src: "192.0.2.1", dst: "198.51.100.1", port: "443", proto: "tcp", reply: true,
      mtu: { mode: "packet", ip_packet_bytes: 1500, ipv4_df: false, reply_ip_packet_bytes: 1400, traffic_class: "best-effort" } };
    const draft = traceDraft(input, "1000")!;
    expect(draft.definition.request!.mtu).toEqual(input.mtu);
    input.mtu!.ip_packet_bytes = 9000;
    expect(draft.definition.request!.mtu!.ip_packet_bytes).toBe(1500);
  });
});
