/**
 * The vie01 office of the demo estate (fixtures/demo-enterprise/estate-v1.yaml)
 * as GET /api/topology draws it: a firewall under the SD-WAN edge, two cores
 * with an HSRP pair of SVIs on seven VLANs, four access switches and a WLAN
 * controller. Built from the fixture with the planner and segments.py.
 */

import type { TopologyModel } from "../../api/types";

export const DEMO_OFFICE: TopologyModel = {
  "snapshot": 1760000000000,
  "nodes": [
    {
      "id": "site:vie01",
      "kind": "site",
      "parent": null,
      "label": "vie01"
    },
    {
      "id": "block:vie01:campus",
      "kind": "block",
      "parent": "site:vie01",
      "label": "Campus",
      "block_kind": "campus",
      "faces": []
    },
    {
      "id": "block:vie01:firewall:campus+other+wan-edge",
      "kind": "block",
      "parent": "site:vie01",
      "label": "Firewall (Campus, Other, WAN edge)",
      "block_kind": "firewall",
      "faces": [
        "campus",
        "other",
        "wan-edge"
      ]
    },
    {
      "id": "block:vie01:other",
      "kind": "block",
      "parent": "site:vie01",
      "label": "Other",
      "block_kind": "other",
      "faces": []
    },
    {
      "id": "block:vie01:wan-edge",
      "kind": "block",
      "parent": "site:vie01",
      "label": "WAN edge",
      "block_kind": "wan-edge",
      "faces": []
    },
    {
      "id": "dev:vie01-acc-01",
      "kind": "device",
      "parent": "block:vie01:other",
      "label": "vie01-acc-01",
      "role": "switch",
      "tier": null,
      "partition": null,
      "depth": 3,
      "mgmt_ip": "10.11.99.11",
      "vendor": "cisco",
      "model": "iosxe"
    },
    {
      "id": "dev:vie01-acc-02",
      "kind": "device",
      "parent": "block:vie01:other",
      "label": "vie01-acc-02",
      "role": "switch",
      "tier": null,
      "partition": null,
      "depth": 3,
      "mgmt_ip": "10.11.99.12",
      "vendor": "cisco",
      "model": "iosxe"
    },
    {
      "id": "dev:vie01-acc-03",
      "kind": "device",
      "parent": "block:vie01:other",
      "label": "vie01-acc-03",
      "role": "switch",
      "tier": null,
      "partition": null,
      "depth": 3,
      "mgmt_ip": "10.11.99.13",
      "vendor": "cisco",
      "model": "iosxe"
    },
    {
      "id": "dev:vie01-acc-04",
      "kind": "device",
      "parent": "block:vie01:other",
      "label": "vie01-acc-04",
      "role": "switch",
      "tier": null,
      "partition": null,
      "depth": 3,
      "mgmt_ip": "10.11.99.14",
      "vendor": "cisco",
      "model": "iosxe"
    },
    {
      "id": "dev:vie01-core-01",
      "kind": "device",
      "parent": "block:vie01:other",
      "label": "vie01-core-01",
      "role": "router",
      "tier": null,
      "partition": null,
      "depth": 2,
      "mgmt_ip": "10.11.99.1",
      "vendor": "cisco",
      "model": "nxos"
    },
    {
      "id": "dev:vie01-core-02",
      "kind": "device",
      "parent": "block:vie01:campus",
      "label": "vie01-core-02",
      "role": "router",
      "tier": null,
      "partition": null,
      "depth": 2,
      "mgmt_ip": "10.11.99.2",
      "vendor": "cisco",
      "model": "nxos"
    },
    {
      "id": "dev:vie01-fgt-01",
      "kind": "device",
      "parent": "block:vie01:firewall:campus+other+wan-edge",
      "label": "vie01-fgt-01",
      "role": "firewall",
      "tier": "firewall",
      "partition": 0,
      "depth": 1,
      "mgmt_ip": "10.11.99.21",
      "vendor": "fortinet",
      "model": "fortigate"
    },
    {
      "id": "dev:vie01-vce-01",
      "kind": "device",
      "parent": "block:vie01:wan-edge",
      "label": "vie01-vce-01",
      "role": "sdwan-edge",
      "tier": "sdwan-edge",
      "partition": 1,
      "depth": 0,
      "mgmt_ip": "10.11.99.22",
      "vendor": "vmware",
      "model": "velocloud-edge"
    },
    {
      "id": "dev:vie01-wlc-01",
      "kind": "device",
      "parent": "block:vie01:campus",
      "label": "vie01-wlc-01",
      "role": "controller",
      "tier": "wireless",
      "partition": 1,
      "depth": 3,
      "mgmt_ip": "10.11.99.23",
      "vendor": "cisco",
      "model": "wlc"
    }
  ],
  "cables": [
    {
      "from": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/11"
      },
      "id": "dev:vie01-acc-01|TenGigabitEthernet1/1/1~dev:vie01-core-01|ethernet1/11",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-01",
        "port": "TenGigabitEthernet1/1/1"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/11"
      },
      "id": "dev:vie01-acc-01|TenGigabitEthernet1/1/2~dev:vie01-core-02|ethernet1/11",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-01",
        "port": "TenGigabitEthernet1/1/2"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/12"
      },
      "id": "dev:vie01-acc-02|TenGigabitEthernet1/1/1~dev:vie01-core-01|ethernet1/12",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-02",
        "port": "TenGigabitEthernet1/1/1"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/12"
      },
      "id": "dev:vie01-acc-02|TenGigabitEthernet1/1/2~dev:vie01-core-02|ethernet1/12",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-02",
        "port": "TenGigabitEthernet1/1/2"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/13"
      },
      "id": "dev:vie01-acc-03|TenGigabitEthernet1/1/1~dev:vie01-core-01|ethernet1/13",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-03",
        "port": "TenGigabitEthernet1/1/1"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/13"
      },
      "id": "dev:vie01-acc-03|TenGigabitEthernet1/1/2~dev:vie01-core-02|ethernet1/13",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-03",
        "port": "TenGigabitEthernet1/1/2"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/14"
      },
      "id": "dev:vie01-acc-04|TenGigabitEthernet1/1/1~dev:vie01-core-01|ethernet1/14",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-04",
        "port": "TenGigabitEthernet1/1/1"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/14"
      },
      "id": "dev:vie01-acc-04|TenGigabitEthernet1/1/2~dev:vie01-core-02|ethernet1/14",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-acc-04",
        "port": "TenGigabitEthernet1/1/2"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/1"
      },
      "id": "dev:vie01-core-01|ethernet1/1~dev:vie01-core-02|ethernet1/1",
      "lateral": true,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/1"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-fgt-01",
        "port": "port1"
      },
      "id": "dev:vie01-core-01|ethernet1/3~dev:vie01-fgt-01|port1",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-core-01",
        "port": "ethernet1/3"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-fgt-01",
        "port": "port2"
      },
      "id": "dev:vie01-core-02|ethernet1/3~dev:vie01-fgt-01|port2",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/3"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-core-02",
        "port": "ethernet1/4"
      },
      "id": "dev:vie01-core-02|ethernet1/4~dev:vie01-wlc-01|TenGigabitEthernet0/0/0",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 10000,
      "to": {
        "dev": "dev:vie01-wlc-01",
        "port": "TenGigabitEthernet0/0/0"
      }
    },
    {
      "from": {
        "dev": "dev:vie01-vce-01",
        "port": "ge2"
      },
      "id": "dev:vie01-fgt-01|port3~dev:vie01-vce-01|ge2",
      "lateral": false,
      "source": "fixture",
      "speed_mbps": 1000,
      "to": {
        "dev": "dev:vie01-fgt-01",
        "port": "port3"
      }
    }
  ],
  "exits": [],
  "lags": [],
  "split_groups": [],
  "clients": [],
  "vlans": [
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-acc-01",
      "name": "users",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-users",
      "svi": null,
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-acc-01",
      "name": "voice",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-voice",
      "svi": null,
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-acc-01",
      "name": "printers",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-printers",
      "svi": null,
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-acc-01",
      "name": "mgmt",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-mgmt",
      "svi": null,
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-acc-01",
      "name": "guest",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-guest",
      "svi": null,
      "vid": 900
    },
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-acc-02",
      "name": "users",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-users",
      "svi": null,
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-acc-02",
      "name": "voice",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-voice",
      "svi": null,
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-acc-02",
      "name": "printers",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-printers",
      "svi": null,
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-acc-02",
      "name": "mgmt",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-mgmt",
      "svi": null,
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-acc-02",
      "name": "guest",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-guest",
      "svi": null,
      "vid": 900
    },
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-acc-03",
      "name": "users",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-users",
      "svi": null,
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-acc-03",
      "name": "voice",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-voice",
      "svi": null,
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-acc-03",
      "name": "printers",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-printers",
      "svi": null,
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-acc-03",
      "name": "mgmt",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-mgmt",
      "svi": null,
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-acc-03",
      "name": "guest",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-guest",
      "svi": null,
      "vid": 900
    },
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-acc-04",
      "name": "users",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-users",
      "svi": null,
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-acc-04",
      "name": "voice",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-voice",
      "svi": null,
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-acc-04",
      "name": "printers",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-printers",
      "svi": null,
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-acc-04",
      "name": "mgmt",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-mgmt",
      "svi": null,
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-acc-04",
      "name": "guest",
      "native": [],
      "ports": [
        "TenGigabitEthernet1/1/1",
        "TenGigabitEthernet1/1/2"
      ],
      "segment": "vie01-guest",
      "svi": null,
      "vid": 900
    },
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-core-01",
      "name": "users",
      "native": [],
      "ports": [
        "ethernet1/1",
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-users",
      "svi": "vlan10",
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-core-01",
      "name": "voice",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-voice",
      "svi": "vlan20",
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-core-01",
      "name": "printers",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-printers",
      "svi": "vlan30",
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-servers",
      "dev": "dev:vie01-core-01",
      "name": "servers",
      "native": [],
      "ports": [],
      "segment": "vie01-servers",
      "svi": "vlan40",
      "vid": 40
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-core-01",
      "name": "mgmt",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-mgmt",
      "svi": "vlan99",
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-fw-transit",
      "dev": "dev:vie01-core-01",
      "name": "fw-transit",
      "native": [],
      "ports": [
        "ethernet1/3"
      ],
      "segment": "vie01-fw-transit",
      "svi": "vlan250",
      "vid": 250
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-core-01",
      "name": "guest",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-guest",
      "svi": "vlan900",
      "vid": 900
    },
    {
      "bd": "l2seg:vie01-users",
      "dev": "dev:vie01-core-02",
      "name": "users",
      "native": [],
      "ports": [
        "ethernet1/1",
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14",
        "ethernet1/4"
      ],
      "segment": "vie01-users",
      "svi": "vlan10",
      "vid": 10
    },
    {
      "bd": "l2seg:vie01-voice",
      "dev": "dev:vie01-core-02",
      "name": "voice",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-voice",
      "svi": "vlan20",
      "vid": 20
    },
    {
      "bd": "l2seg:vie01-printers",
      "dev": "dev:vie01-core-02",
      "name": "printers",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-printers",
      "svi": "vlan30",
      "vid": 30
    },
    {
      "bd": "l2seg:vie01-servers",
      "dev": "dev:vie01-core-02",
      "name": "servers",
      "native": [],
      "ports": [],
      "segment": "vie01-servers",
      "svi": "vlan40",
      "vid": 40
    },
    {
      "bd": "l2seg:vie01-mgmt",
      "dev": "dev:vie01-core-02",
      "name": "mgmt",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14"
      ],
      "segment": "vie01-mgmt",
      "svi": "vlan99",
      "vid": 99
    },
    {
      "bd": "l2seg:vie01-fw-transit",
      "dev": "dev:vie01-core-02",
      "name": "fw-transit",
      "native": [],
      "ports": [],
      "segment": "vie01-fw-transit",
      "svi": "vlan250",
      "vid": 250
    },
    {
      "bd": "l2seg:vie01-guest",
      "dev": "dev:vie01-core-02",
      "name": "guest",
      "native": [],
      "ports": [
        "ethernet1/11",
        "ethernet1/12",
        "ethernet1/13",
        "ethernet1/14",
        "ethernet1/3",
        "ethernet1/4"
      ],
      "segment": "vie01-guest",
      "svi": "vlan900",
      "vid": 900
    }
  ],
  "subnets": [
    {
      "af": 4,
      "cidr": "10.11.10.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan10",
          "ip": "10.11.10.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan10",
          "ip": "10.11.10.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan10",
          "ip": "10.11.10.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan10",
          "ip": "10.11.10.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.20.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan20",
          "ip": "10.11.20.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan20",
          "ip": "10.11.20.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan20",
          "ip": "10.11.20.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan20",
          "ip": "10.11.20.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.250.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan250",
          "ip": "10.11.250.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan250",
          "ip": "10.11.250.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan250",
          "ip": "10.11.250.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan250",
          "ip": "10.11.250.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.251.0/30",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-vce-01",
          "fhrp": null,
          "iface": "ge2",
          "ip": "10.11.251.2"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.255.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "loopback0",
          "ip": "10.11.255.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "loopback0",
          "ip": "10.11.255.2"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.30.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan30",
          "ip": "10.11.30.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan30",
          "ip": "10.11.30.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan30",
          "ip": "10.11.30.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan30",
          "ip": "10.11.30.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.40.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan40",
          "ip": "10.11.40.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan40",
          "ip": "10.11.40.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan40",
          "ip": "10.11.40.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan40",
          "ip": "10.11.40.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.99.0/24",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-core-01",
          "fhrp": "hsrp",
          "iface": "vlan99",
          "ip": "10.11.99.1"
        },
        {
          "dev": "dev:vie01-core-01",
          "fhrp": null,
          "iface": "vlan99",
          "ip": "10.11.99.2"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": "hsrp",
          "iface": "vlan99",
          "ip": "10.11.99.1"
        },
        {
          "dev": "dev:vie01-core-02",
          "fhrp": null,
          "iface": "vlan99",
          "ip": "10.11.99.3"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.254.11.0/30",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-vce-01",
          "fhrp": null,
          "iface": "vcmp-dc1",
          "ip": "10.254.11.1"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.254.11.4/30",
      "domain": "corp",
      "members": [
        {
          "dev": "dev:vie01-vce-01",
          "fhrp": null,
          "iface": "vcmp-dc2",
          "ip": "10.254.11.5"
        }
      ],
      "vrf": "corp"
    },
    {
      "af": 4,
      "cidr": "10.11.250.0/24",
      "domain": null,
      "members": [
        {
          "dev": "dev:vie01-fgt-01",
          "fhrp": null,
          "iface": "port1",
          "ip": "10.11.250.6"
        }
      ],
      "vrf": "root"
    },
    {
      "af": 4,
      "cidr": "10.11.251.0/30",
      "domain": null,
      "members": [
        {
          "dev": "dev:vie01-fgt-01",
          "fhrp": null,
          "iface": "port3",
          "ip": "10.11.251.1"
        }
      ],
      "vrf": "root"
    },
    {
      "af": 4,
      "cidr": "172.31.11.0/24",
      "domain": null,
      "members": [
        {
          "dev": "dev:vie01-fgt-01",
          "fhrp": null,
          "iface": "port2",
          "ip": "172.31.11.1"
        }
      ],
      "vrf": "root"
    }
  ],
  "segments": [
    {
      "attachments": [],
      "bd": "l2seg:vie01-users",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-acc-01",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-02",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-03",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-04",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/1",
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-02",
          "native": [],
          "ports": [
            "ethernet1/1",
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14",
            "ethernet1/4"
          ]
        }
      ],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.10.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.10.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan10",
          "ip": "10.11.10.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.10.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan10",
          "ip": "10.11.10.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.10.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan10",
          "ip": "10.11.10.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.10.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan10",
          "ip": "10.11.10.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-users",
      "vid": 10
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-voice",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-acc-01",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-02",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-03",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-04",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-02",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        }
      ],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.20.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.20.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan20",
          "ip": "10.11.20.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.20.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan20",
          "ip": "10.11.20.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.20.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan20",
          "ip": "10.11.20.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.20.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan20",
          "ip": "10.11.20.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-voice",
      "vid": 20
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-printers",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-acc-01",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-02",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-03",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-04",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-02",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        }
      ],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.30.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.30.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan30",
          "ip": "10.11.30.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.30.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan30",
          "ip": "10.11.30.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.30.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan30",
          "ip": "10.11.30.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.30.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan30",
          "ip": "10.11.30.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-printers",
      "vid": 30
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-servers",
      "carriers": [],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.40.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.40.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan40",
          "ip": "10.11.40.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.40.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan40",
          "ip": "10.11.40.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.40.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan40",
          "ip": "10.11.40.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.40.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan40",
          "ip": "10.11.40.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-servers",
      "vid": 40
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-mgmt",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-acc-01",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-02",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-03",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-04",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-02",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        }
      ],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.99.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.99.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan99",
          "ip": "10.11.99.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.99.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan99",
          "ip": "10.11.99.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.99.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan99",
          "ip": "10.11.99.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.99.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan99",
          "ip": "10.11.99.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-mgmt",
      "vid": 99
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-fw-transit",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/3"
          ]
        }
      ],
      "cidr_basis": "gateway",
      "cidrs": [
        "10.11.250.0/24"
      ],
      "clients": 0,
      "gateways": [
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.250.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan250",
          "ip": "10.11.250.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.250.0/24",
          "dev": "dev:vie01-core-01",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan250",
          "ip": "10.11.250.2",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.250.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": "hsrp",
          "iface": "vlan250",
          "ip": "10.11.250.1",
          "vrf": "corp"
        },
        {
          "af": 4,
          "basis": "svi",
          "cidr": "10.11.250.0/24",
          "dev": "dev:vie01-core-02",
          "domain": "corp",
          "fhrp": null,
          "iface": "vlan250",
          "ip": "10.11.250.3",
          "vrf": "corp"
        }
      ],
      "name": "vie01-fw-transit",
      "vid": 250
    },
    {
      "attachments": [],
      "bd": "l2seg:vie01-guest",
      "carriers": [
        {
          "access": [],
          "dev": "dev:vie01-acc-01",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-02",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-03",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-acc-04",
          "native": [],
          "ports": [
            "TenGigabitEthernet1/1/1",
            "TenGigabitEthernet1/1/2"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-01",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14"
          ]
        },
        {
          "access": [],
          "dev": "dev:vie01-core-02",
          "native": [],
          "ports": [
            "ethernet1/11",
            "ethernet1/12",
            "ethernet1/13",
            "ethernet1/14",
            "ethernet1/3",
            "ethernet1/4"
          ]
        }
      ],
      "cidr_basis": null,
      "cidrs": [],
      "clients": 0,
      "gateways": [
        {
          "af": null,
          "basis": "svi",
          "cidr": null,
          "dev": "dev:vie01-core-01",
          "domain": null,
          "fhrp": null,
          "iface": "vlan900",
          "ip": null,
          "vrf": null
        },
        {
          "af": null,
          "basis": "svi",
          "cidr": null,
          "dev": "dev:vie01-core-02",
          "domain": null,
          "fhrp": null,
          "iface": "vlan900",
          "ip": null,
          "vrf": null
        }
      ],
      "name": "vie01-guest",
      "vid": 900
    }
  ]
};
