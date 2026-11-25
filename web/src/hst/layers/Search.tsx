import { useCallback } from "react";
import UnifiedSearch from "../../search/UnifiedSearch";
import type { Kind, SearchHit } from "../../search/types";
import { localHit, type LocalGroup } from "../../search/useSearch";
import type { Scene } from "../render/scene";
import { sceneHit, search, type Hit } from "./find";

interface Props {
  scene: Scene;
  /** Changes when the scene's rows change, so the results follow the run. */
  version: number;
  onPick(hit: Hit): void;
}

/** The server kinds whose hits can name a site or a device of the scene. */
const KINDS: readonly Kind[] = ["device", "site", "interface", "ip_address", "arp", "mac"];

/** The site, block or device of the scene a server hit stands for: its target,
 *  itself, or the device of its row; null when the scene holds none of them. */
function pickOf(scene: Scene, hit: SearchHit): Hit | null {
  const device = hit.fields.device_uid;
  for (const uid of [hit.target?.uid, hit.uid, typeof device === "string" ? device : null]) {
    const found = uid ? sceneHit(scene, uid) : null;
    if (found) return found;
  }
  return null;
}

/** The twin's search: the sites, blocks and devices of the scene first, then
 *  the server's hits that name one of them. */
export default function Search({ scene, version, onPick }: Props) {
  const local = useCallback(
    (text: string): LocalGroup[] => [
      {
        id: "scene",
        title: "Sites, blocks and devices",
        items: search(scene, text).map((h) => localHit({ key: `${h.kind}:${h.uid}`, uid: h.uid, name: h.label, kind: h.kind })),
      },
    ],
    // the version stands for the scene's rows, which change in place
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scene, version],
  );
  const accept = useCallback(
    (hit: SearchHit) => pickOf(scene, hit) !== null,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scene, version],
  );
  const open = useCallback(
    (hit: SearchHit) => {
      const picked = hit.source === "local" && hit.uid ? sceneHit(scene, hit.uid) : pickOf(scene, hit);
      if (picked) onPick(picked);
    },
    [scene, onPick],
  );
  return (
    <div className="hst-search" data-version={version}>
      <UnifiedSearch
        label="Search the map"
        defaultKinds={KINDS}
        localGroups={local}
        accept={accept}
        onOpen={open}
        clearOnOpen
        popover
      />
    </div>
  );
}
