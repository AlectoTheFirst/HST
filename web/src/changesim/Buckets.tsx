/** The lists that both panes draw out of a tool result. */

import { DeviceName } from "../shell/deviceNames";
import type { ReactNode } from "react";
import type { ImpactBucket, ImpactDevice } from "./assessImpact";
import "../diff/diff.css";
import "./changesim.css";

export function DeviceIdentity({ device }: { device: ImpactDevice }) {
  const meta = [device.vendor, device.platform, device.model, device.role, device.software_version]
    .filter((v): v is string => !!v)
    .join(", ");
  return (
    <div className="chgsim-device">
      <div className="chgsim-devicename">{device.hostname ?? <DeviceName uid={device.uid} />}</div>
      {meta && <div className="chgsim-devicemeta">{meta}</div>}
    </div>
  );
}

export function BucketSection<T>({
  title,
  bucket,
  render,
}: {
  title: string;
  bucket: Omit<ImpactBucket<T>, "count"> & {
    count: number | null;
    count_decimal?: string;
    address_count_decimal?: string;
  };
  render: (item: T) => ReactNode;
}) {
  return (
    <section className="chgsim-bucket">
      <div className="chgsim-buckethead">
        <h3>{title}</h3>
        <span className="chgsim-bucketcount">
          {bucket.address_count_decimal ?? bucket.count_decimal ?? bucket.count}
          {bucket.address_count_decimal !== undefined ? " addresses" : ""}
        </span>
      </div>
      {bucket.count === 0 ? (
        <p className="chgsim-bucketempty">none</p>
      ) : (
        <ul className="chgsim-bucketlist">
          {bucket.items.map((item, i) => (
            <li key={i}>{render(item)}</li>
          ))}
        </ul>
      )}
      {bucket.truncated && (
        <p className="chgsim-truncated">
          {`${bucket.items.length} of ${bucket.count_decimal ?? bucket.count} listed`}
        </p>
      )}
    </section>
  );
}

/** `count` is the whole number of rows when the list itself is capped. */
export function ListSection<T>({
  title,
  items,
  render,
  count,
  truncated,
}: {
  title: string;
  items: readonly T[];
  render: (item: T) => ReactNode;
  count?: number;
  truncated?: boolean;
}) {
  if (items.length === 0) return null;
  return (
    <section className="chgsim-bucket">
      <div className="chgsim-buckethead">
        <h3>{title}</h3>
        <span className="chgsim-bucketcount">{count ?? items.length}</span>
      </div>
      <ul className="chgsim-bucketlist">
        {items.map((item, i) => (
          <li key={i}>{render(item)}</li>
        ))}
      </ul>
      {truncated && (
        <p className="chgsim-truncated">
          {count === undefined ? `first ${items.length} listed` : `${items.length} of ${count} listed`}
        </p>
      )}
    </section>
  );
}
