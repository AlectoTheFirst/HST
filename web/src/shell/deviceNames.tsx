/**
 * Device hostnames for the UI. A device's graph uid is its serial-based
 * identity (`dev:<serial>`, core/uid.py).
 *
 * The app shell loads the map once (GET /api/explore/device-names) and provides
 * it.
 */

import { createContext, useContext, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

type DeviceNames = Readonly<Record<string, string>>;

const EMPTY: DeviceNames = Object.freeze({});
const DeviceNamesContext = createContext<DeviceNames>(EMPTY);

export function DeviceNamesProvider({ children }: { children: ReactNode }) {
  const names = useQuery({
    queryKey: ["device-names"],
    queryFn: () => api<{ names: Record<string, string> }>("/explore/device-names"),
    staleTime: 5 * 60_000,
  });
  return <DeviceNamesContext.Provider value={names.data?.names ?? EMPTY}>{children}</DeviceNamesContext.Provider>;
}

export function useDeviceNames(): DeviceNames {
  return useContext(DeviceNamesContext);
}

const DEVICE = String.raw`dev:(?:x:[a-z0-9._-]+:)?[a-z0-9._-]+`;
// A device uid inside text, not part of a longer uid.
const DEVICE_UID = new RegExp(String.raw`(?<![\w:~.-])${DEVICE}`, "g");
// A VRF of a device: `vrf:<device uid>:<name>` (core/uid.py `vrf`).
const VRF_UID = new RegExp(String.raw`(?<![\w:~.-])vrf:(${DEVICE}):([^\s,;()'"]+)`, "g");
const VRF_EXACT = new RegExp(String.raw`^vrf:(${DEVICE}):(.+)$`);
const INTERFACE_UID = new RegExp(String.raw`^(${DEVICE})/if/(.+)$`);

/** The known device uid at the start of `match`, and the text after it. A uid
 *  followed by sentence punctuation still matches: the trailing dots and
 *  dashes are tried off one at a time. */
function knownDevice(match: string, names: DeviceNames): [string, string] | null {
  for (let end = match.length; end > 4; end--) {
    const candidate = match.slice(0, end);
    if (names[candidate]) return [names[candidate], match.slice(end)];
    if (!/[.-]$/.test(candidate)) break;
  }
  return null;
}

/** A uid as a reader names it: a device by hostname, a device's VRF as
 *  "<vrf> on <hostname>", a device's interface as "<hostname> <interface>".
 *  Any other uid, or one whose device has no hostname, is itself. */
export function uidLabel(uid: string, names: DeviceNames): string {
  if (names[uid]) return names[uid];
  const iface = INTERFACE_UID.exec(uid);
  if (iface && names[iface[1]]) return `${names[iface[1]]} ${iface[2]}`;
  const vrf = VRF_EXACT.exec(uid);
  if (vrf && names[vrf[1]]) return `${vrf[2]} on ${names[vrf[1]]}`;
  return uid;
}

/** `text` with each device uid, and each VRF uid of a device, named as
 *  `uidLabel` names it. */
export function withDeviceNames(text: string, names: DeviceNames): string {
  if (!text.includes("dev:")) return text;
  return text
    .replace(VRF_UID, (match, device: string, vrf: string) => {
      if (!names[device]) return match;
      const trailing = /[.]+$/.exec(vrf)?.[0] ?? "";
      return `${vrf.slice(0, vrf.length - trailing.length)} on ${names[device]}${trailing}`;
    })
    .replace(DEVICE_UID, (match) => {
      const known = knownDevice(match, names);
      return known ? known[0] + known[1] : match;
    });
}

/** A device, or a device's VRF or interface, shown as `uidLabel` names it,
 *  with the uid in the tooltip. */
export function DeviceName({ uid }: { uid: string }) {
  const names = useDeviceNames();
  const label = uidLabel(uid, names);
  return <span title={label === uid ? undefined : uid}>{label}</span>;
}

/** Backend prose (a detail, a note, a warning) with device uids shown by hostname. */
export function DeviceText({ text }: { text: string }) {
  return <>{withDeviceNames(text, useDeviceNames())}</>;
}

/** A function that names the devices in a text or a uid (`withDeviceNames`),
 *  for components that build their text in code. */
export function useNamer(): (text: string) => string {
  const names = useDeviceNames();
  return (text) => withDeviceNames(text, names);
}
