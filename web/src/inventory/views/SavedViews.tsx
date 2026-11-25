import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { inventoryApi, type DeviceListQuery, type SavedViewCreate, type SavedViewView } from "../../api/inventory";
import { inventoryKeys, invalidateAfterInventoryWrite } from "../queryKeys";
import { ErrorNotice } from "../ui/ErrorNotice";

export function SavedViews({ query, columns, onSelect }: {
  query: DeviceListQuery;
  columns: string[];
  onSelect: (view: SavedViewView) => void;
}) {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState("");
  const views = useQuery({ queryKey: inventoryKeys.views.list(), queryFn: inventoryApi.listViews });
  const selected = views.data?.find(v => v.id === chosen);
  const { q, site_id, connection_id, platform, collection_state, placement_state, lifecycle } = query;
  const draft: SavedViewCreate = { name, filter: { version: 1, q, site_id, connection_id, platform, collection_state, placement_state, lifecycle }, sort: query.sort, direction: query.direction, columns };
  const mutation = useMutation({
    mutationFn: async (action: "create" | "update" | "rename" | "delete"): Promise<unknown> =>
      action === "create" ? inventoryApi.createView(draft)
        : action === "delete" ? inventoryApi.deleteView(selected!.id, selected!.revision)
          : inventoryApi.patchView(selected!.id, { ...(action === "rename" ? { name } : draft), expected_revision: selected!.revision }),
    onSuccess: async (_result, action) => {
      await invalidateAfterInventoryWrite(client, "view");
      if (action === "delete") { setChosen(""); setName(""); }
    },
  });
  return (
    <details className="inv-menu">
      <summary className="secondary">Saved views</summary>
      <div className="inv-menu-panel">
        <ErrorNotice error={views.error} retry={() => void views.refetch()} />
        <label className="inv-field"><span>Saved view</span>
          <select value={chosen} onChange={e => {
            setChosen(e.target.value);
            const view = views.data?.find(v => v.id === e.target.value);
            if (view) { setName(view.name); onSelect(view); }
          }}>
            <option value="">Choose a view</option>
            {views.data?.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
          </select>
        </label>
        <label className="inv-field"><span>View name</span><input value={name} onChange={e => setName(e.target.value)} /></label>
        <div className="inv-actions">
          <button type="button" className="secondary" disabled={!name.trim() || mutation.isPending} onClick={() => mutation.mutate("create")}>Save new view</button>
          {selected && <>
            <button type="button" className="secondary" disabled={!name.trim() || mutation.isPending} onClick={() => mutation.mutate("rename")}>Rename view</button>
            <button type="button" className="secondary" disabled={!name.trim() || mutation.isPending} onClick={() => mutation.mutate("update")}>Update view</button>
            <button type="button" className="secondary inv-danger" disabled={mutation.isPending} onClick={() => mutation.mutate("delete")}>Delete view</button>
          </>}
        </div>
        <ErrorNotice error={mutation.error} />
      </div>
    </details>
  );
}
