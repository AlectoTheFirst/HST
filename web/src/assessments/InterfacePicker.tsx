import { useState } from "react";
import { ObjectPicker } from "./ObjectPicker";
import type { DiscoveryObject } from "./guided";

interface PickedDevice {
  uid: string;
  name: string;
}

/** A device search, then a search of the interfaces of the selected device. */
export function InterfacePicker({
  snapshot,
  deviceLabel,
  interfaceLabel,
  device,
  selectedUids = [],
  assessmentId,
  onSelect,
}: {
  snapshot: string;
  deviceLabel: string;
  interfaceLabel: string;
  /** The device UID of the first interface search. */
  device?: string;
  selectedUids?: string[];
  assessmentId?: string;
  onSelect: (item: DiscoveryObject) => void;
}) {
  return (
    <DeviceInterfaces
      key={`${snapshot}:${device ?? ""}`}
      snapshot={snapshot}
      deviceLabel={deviceLabel}
      interfaceLabel={interfaceLabel}
      device={device}
      selectedUids={selectedUids}
      assessmentId={assessmentId}
      onSelect={onSelect}
    />
  );
}

function DeviceInterfaces({
  snapshot,
  deviceLabel,
  interfaceLabel,
  device,
  selectedUids,
  assessmentId,
  onSelect,
}: {
  snapshot: string;
  deviceLabel: string;
  interfaceLabel: string;
  device?: string;
  selectedUids: string[];
  assessmentId?: string;
  onSelect: (item: DiscoveryObject) => void;
}) {
  const [picked, setPicked] = useState<PickedDevice | null>(
    device ? { uid: device, name: device } : null,
  );
  if (!picked)
    return (
      <ObjectPicker
        snapshot={snapshot}
        kind="device"
        label={deviceLabel}
        assessmentId={assessmentId}
        onSelect={(item) => setPicked({ uid: item.uid, name: item.name })}
      />
    );
  return (
    <div className="assessment-interface-picker">
      <p>
        Device <strong>{picked.name}</strong>{" "}
        <button type="button" onClick={() => setPicked(null)}>
          Change device
        </button>
      </p>
      <ObjectPicker
        snapshot={snapshot}
        kind="interface"
        device={picked.uid}
        label={interfaceLabel}
        assessmentId={assessmentId}
        selectedUids={selectedUids}
        onSelect={onSelect}
      />
    </div>
  );
}
