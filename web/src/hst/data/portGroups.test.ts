import { describe, expect, it } from "vitest";
import { groupKey, portGroups } from "./portGroups";

describe("the port groups", () => {
  it("strip the trailing port number like the server", () => {
    expect(["Ethernet1/12", "eth0", "Port 17", "ge-0/0/3", "mgmt"].map(groupKey)).toEqual(["Ethernet1/", "eth", "Port ", "ge-0/0/", "mgmt"]);
  });

  it("count states, connected ports and the name range in natural order", () => {
    const ports = [
      { uid: "p10", device_uid: "d", name: "Eth1/10", oper_status: "up" },
      { uid: "p2", device_uid: "d", name: "Eth1/2", oper_status: "down" },
      { uid: "p3", device_uid: "d", name: "Eth1/3", admin_status: "down", oper_status: "up" },
      { uid: "m", device_uid: "d", name: "mgmt0" },
    ];
    const rows = portGroups(ports, [{ a_port: "p10", b_port: "x" }]);
    expect(rows).toEqual([
      { device_uid: "d", tile: undefined, group_key: "Eth1/", first_name: "Eth1/2", last_name: "Eth1/10", port_count: 3, up: 1, down: 1, admin_down: 1, connected: 1 },
      { device_uid: "d", tile: undefined, group_key: "mgmt", first_name: "mgmt0", last_name: "mgmt0", port_count: 1, up: 0, down: 0, admin_down: 0, connected: 0 },
    ]);
  });
});
