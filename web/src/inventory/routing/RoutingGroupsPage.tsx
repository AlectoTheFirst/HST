import { DeviceName } from "../../shell/deviceNames";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { inventoryApi, type RoutingGroupView, type PreviewRequest } from "../../api/inventory";
import { inventoryKeys, invalidateAfterInventoryWrite } from "../queryKeys";
import { useCapabilities, useInventoryDraft } from "../shared";
import { Badge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card, ConfirmDialog, PageHeader } from "../ui/Page";
import { formatTime } from "../ui/format";

function GroupEditor({ group, onClose }: { group: RoutingGroupView; onClose: () => void }) {
  const client = useQueryClient();
  const [name, setName, clearName] = useInventoryDraft(`routing:${group.id}:name`, group.display_name);
  const [description, setDescription, clearDescription] = useInventoryDraft(`routing:${group.id}:description`, group.description);
  const [revision, , clearRevision] = useInventoryDraft(`routing:${group.id}:revision`, group.revision);
  const discard = () => { clearName(); clearDescription(); clearRevision(); };
  const save = useMutation({
    mutationFn: () => inventoryApi.patchRoutingGroup(group.id, { display_name: name, description, expected_revision: revision }),
    onSuccess: async () => { await invalidateAfterInventoryWrite(client, "routing-group"); discard(); onClose(); },
  });
  return (
    <form className="inv-form" onSubmit={e => { e.preventDefault(); save.mutate(); }}>
      <label className="inv-field"><span>Group name</span><input required value={name} onChange={e => setName(e.target.value)} /></label>
      <label className="inv-field"><span>Description</span><textarea value={description} onChange={e => setDescription(e.target.value)} /></label>
      <ErrorNotice error={save.error} />
      <div className="inv-actions">
        <button type="submit" className="primary" disabled={save.isPending}>Save group</button>
        <button type="button" className="secondary" onClick={() => { discard(); onClose(); }}>Discard changes</button>
      </div>
    </form>
  );
}

function GroupCreator({ onClose }: { onClose: () => void }) {
  const client = useQueryClient();
  const [name, setName, clearName] = useInventoryDraft("routing:create:name", "");
  const [description, setDescription, clearDescription] = useInventoryDraft("routing:create:description", "");
  const create = useMutation({
    mutationFn: () => inventoryApi.createRoutingGroup({ display_name: name, description }),
    onSuccess: async () => { await invalidateAfterInventoryWrite(client, "routing-group"); clearName(); clearDescription(); onClose(); },
  });
  return (
    <Card title="New routing group">
      <form className="inv-form" onSubmit={e => { e.preventDefault(); create.mutate(); }}>
        <label className="inv-field"><span>Group name</span><input required value={name} onChange={e => setName(e.target.value)} /></label>
        <label className="inv-field"><span>Description</span><textarea value={description} onChange={e => setDescription(e.target.value)} /></label>
        <ErrorNotice error={create.error} />
        <div className="inv-actions">
          <button type="submit" className="primary" disabled={create.isPending || !name.trim()}>Create group</button>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Card>
  );
}

function AddContexts({ group, initial, onReview }: { group: RoutingGroupView; initial: string; onReview: (request: PreviewRequest) => void }) {
  const [text, setText] = useState(initial);
  const uids = [...new Set(text.split("\n").map(x => x.trim()).filter(Boolean))];
  return (
    <form className="inv-form" onSubmit={e => {
      e.preventDefault();
      onReview({ operation: "edit_routing_members", selection: { ids: [group.id] }, change: { group_id: group.id, add_context_uids: uids, remove_context_uids: [] } });
    }}>
      <label className="inv-field"><span>Context UIDs to add to {group.display_name}</span>
        <textarea value={text} placeholder="One context UID per line" onChange={e => setText(e.target.value)} />
      </label>
      <div className="inv-actions">
        <button type="submit" className="primary" disabled={!uids.length}>Preview adding contexts to {group.display_name}</button>
      </div>
    </form>
  );
}

function GroupCard({ group: g, canEdit, initialContexts, onReview, onArchive }: {
  group: RoutingGroupView; canEdit: boolean; initialContexts: string; onReview: (request: PreviewRequest) => void; onArchive: () => void;
}) {
  const [panel, setPanel] = useState<"add" | "edit" | null>(initialContexts && !g.archived_at ? "add" : null);
  const toggle = (next: "add" | "edit") => setPanel(panel === next ? null : next);
  return (
    <Card title={<>{g.display_name} {g.archived_at && <Badge>Archived</Badge>}</>}
      actions={canEdit && !g.archived_at && <>
        <button type="button" className="secondary" aria-expanded={panel === "add"} onClick={() => toggle("add")}>Add contexts</button>
        <button type="button" className="secondary" aria-expanded={panel === "edit"} onClick={() => toggle("edit")}>Edit group</button>
        <button type="button" className="secondary inv-danger" onClick={onArchive}>Archive</button>
      </>}>
      {g.description && <p>{g.description}</p>}
      <p className="hint">Revision {g.revision}, updated {formatTime(g.updated_at)}</p>
      {panel === "edit" && <GroupEditor key={g.id} group={g} onClose={() => setPanel(null)} />}
      {panel === "add" && <AddContexts group={g} initial={initialContexts} onReview={onReview} />}
      {g.members.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr><th>Context UID</th><th>Observed owner</th><th>Presence</th><th>Added</th>{canEdit && <th className="inv-col-actions">Action</th>}</tr>
            </thead>
            <tbody>
              {g.members.map(m => (
                <tr key={m.context_uid}>
                  <td className="mono">{m.context_uid}</td>
                  <td><DeviceName uid={m.owner_uid} /></td>
                  <td>{m.present ? <Badge tone="ok">Present</Badge> : <Badge tone="warn">Absent</Badge>}</td>
                  <td>{m.actor_id ?? "System"}, {formatTime(m.added_at)}</td>
                  {canEdit && (
                    <td className="inv-col-actions">
                      <button type="button" className="secondary" aria-label={`Remove ${m.context_uid}`}
                        onClick={() => onReview({ operation: "edit_routing_members", selection: { ids: [g.id] }, change: { group_id: g.id, remove_context_uids: [m.context_uid], add_context_uids: [] } })}>Remove</button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export function InventoryRoutingGroupsPage() {
  const { write: canEdit } = useCapabilities();
  const client = useQueryClient();
  const [params] = useSearchParams();
  const initialContexts = params.getAll("context_uid").join("\n");
  const [creating, setCreating] = useState(false);
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const [archive, setArchive] = useState<RoutingGroupView | null>(null);
  const groups = useQuery({ queryKey: inventoryKeys.routingGroups.list(), queryFn: inventoryApi.listRoutingGroups });
  const remove = useMutation({
    mutationFn: () => inventoryApi.deleteRoutingGroup(archive!.id, archive!.revision),
    onSuccess: async () => { await invalidateAfterInventoryWrite(client, "apply"); setArchive(null); },
  });
  return (
    <section className="ops-page inv-page">
      <PageHeader title="Routing groups">
        {canEdit && !creating && <button type="button" className="primary" onClick={() => setCreating(true)}>New group</button>}
      </PageHeader>
      {creating && <GroupCreator onClose={() => setCreating(false)} />}
      <ErrorNotice error={groups.error} retry={() => void groups.refetch()} />
      {groups.isPending && <p className="hint">Loading routing groups</p>}
      {groups.data?.length === 0 && <div className="results"><p className="tableempty">No routing groups</p></div>}
      {groups.data?.map(g => (
        <GroupCard key={g.id} group={g} canEdit={canEdit} initialContexts={initialContexts} onReview={setReview} onArchive={() => { remove.reset(); setArchive(g); }} />
      ))}
      {archive && (
        <ConfirmDialog label={`Archive ${archive.display_name}`} title={`Archive ${archive.display_name}`} confirmLabel="Archive group" danger
          pending={remove.isPending} onConfirm={() => remove.mutate()} onCancel={() => setArchive(null)}>
          <ErrorNotice error={remove.error} />
        </ConfirmDialog>
      )}
      {review && <ImpactReview key={JSON.stringify(review)} request={review} onCancel={() => setReview(null)} onDone={() => setReview(null)} />}
    </section>
  );
}
