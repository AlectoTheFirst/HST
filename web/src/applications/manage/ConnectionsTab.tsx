import { useState } from "react";
import { PinnedSnapshotPicker } from "../../assessments/PinnedSnapshotPicker";
import { ConnectionFields } from "../ApplicationEditor";
import type { ApplicationDraft } from "../useApplicationDraft";
import { groupName, portText, requiredText, serviceOf } from "./connectionText";

export function ConnectionsTab({ editor, locked }: { editor: ApplicationDraft; locked: boolean }) {
  const { draft } = editor;
  const [selected, setSelected] = useState<number | null>(null);
  const [snapshot, setSnapshot] = useState("");
  const connection = selected != null ? draft.connections[selected] : undefined;
  return (
    <div className="apps-split">
      <section aria-label="Connections">
        <div className="apps-section-head">
          <h2>Connections</h2>
          <button
            type="button"
            className="secondary"
            disabled={locked || draft.groups.length < 2}
            onClick={() => {
              editor.addConnection();
              setSelected(draft.connections.length);
            }}
          >
            Add connection
          </button>
        </div>
        {draft.connections.length === 0 ? (
          <p>No connections</p>
        ) : (
          <div className="results inv-table">
            <table>
              <thead>
                <tr>
                  <th>Connection</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Ports</th>
                  <th>Required</th>
                  <th>Service</th>
                </tr>
              </thead>
              <tbody>
                {draft.connections.map((item, index) => (
                  <tr key={index} aria-selected={index === selected}>
                    <td>
                      <button
                        type="button"
                        className="linkish"
                        aria-pressed={index === selected}
                        onClick={() => setSelected(index)}
                      >
                        {item.name}
                      </button>
                    </td>
                    <td>{groupName(draft, item.source)}</td>
                    <td>{groupName(draft, item.destination)}</td>
                    <td>{portText(item)}</td>
                    <td>{requiredText(draft, item)}</td>
                    <td>{serviceOf(draft, item.id)?.name ?? "none"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {connection && selected != null && (
        <aside className="apps-form" aria-label={`Connection ${connection.name}`}>
          <div className="apps-section-head">
            <h2>{connection.name}</h2>
            <button
              type="button"
              className="secondary"
              disabled={locked}
              onClick={() => {
                editor.removeConnection(selected);
                setSelected(null);
              }}
            >
              Delete connection
            </button>
          </div>
          <fieldset disabled={locked}>
            <label className="inv-field">
              <span>Service</span>
              <select
                value={serviceOf(draft, connection.id)?.id ?? ""}
                onChange={(event) => editor.setConnectionService(connection.id, event.target.value)}
              >
                <option value="">None</option>
                {draft.services.map((service) => (
                  <option key={service.id} value={service.id}>
                    {service.name}
                  </option>
                ))}
              </select>
            </label>
            <PinnedSnapshotPicker label="Inventory snapshot" value={snapshot} onChange={setSnapshot} />
            <ConnectionFields
              connection={connection}
              definition={draft}
              snapshot={snapshot}
              onChange={(value) => editor.replaceConnection(selected, value)}
            />
          </fieldset>
        </aside>
      )}
    </div>
  );
}
