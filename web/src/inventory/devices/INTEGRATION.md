# Inventory UI integration

Mount `InventoryLayout` at `/inventory` with an index redirect to `devices`.
Mount the same `InventoryDevicesPage` component at `devices` and `devices/:id`.
It owns the drawer over the list and the full-page detail. Mount
`InventorySitesPage` at `sites` and `InventoryRoutingGroupsPage` at
`routing-groups`. Register the profiles route before the connection ID route.

The profile assignment handoff is `/inventory/connections/profiles` with repeated
`target_id` parameters. Only the target IDs chosen on the devices page are sent.
The assignment preview lists the other devices that each shared target observes.

All requests use the typed inventory client and the central query keys.
Archive and restore need `inventory.write`. Placement and site edits need
`sites.write`. Collection and effective settings need `runs.manage`. Profile and
routing group edits need `sources.write`. The server checks ownership of saved views.

## Shared building blocks

| Module | Purpose |
| --- | --- |
| `shared.ts` | Permission, catalog, action and session draft hooks, and route links. |
| `ui/ErrorNotice.tsx` | The one error banner. It states the error and shows the server message. |
| `ui/ImpactReview.tsx` | The one confirm and apply dialog. It requests the preview when it opens. |
| `ui/Page.tsx` | Page header, card, fact list, stat, modal and confirm dialog. |
| `ui/Badge.tsx`, `ui/format.ts` | Labels and badge tones for backend enum values. |
| `ui/SitePicker.tsx` | Searchable site choice. It searches the server and loads 20 sites at a time. |
| `ui/csv.ts` | CSV read, write and download. |
| `sites/LocationsBrowser.tsx` | Paged locations with filters, bulk mapping and suggested sites. |
| `sites/SiteTransfer.tsx` | CSV import and export of sites and location mappings. |
| `ui/EffectiveSettings.tsx` | Resolved target settings, loaded when opened. |
| `inventory.css` | Styles that the theme classes do not cover. |

Pages use the settings shell and the ops-page classes from `theme.css`:
`.settings-layout`, `.ops-page`, `.editorcard`, `.results`, `.badge`, `.banner`,
`.primary`, `.secondary`, `.tabs` and `.modal-card`.

Non-secret site and routing form drafts persist in session storage, scoped to the
signed-in username. Discard buttons clear edit drafts. A successful save clears the
create draft. A failed mutation keeps the input and the captured revision.

Cached facts from a 503 response render as a separate section. They are labeled
as cached and are kept apart from a fresh graph read. Detail data from the last
successful load stays visible when a refresh fails.

Sites and locations page through `GET /sites/search` and `GET /locations/search`.
Bulk writes go through `POST /sites/import` and `POST /locations/bindings`. Each
bulk write runs as a dry run first, and the confirm dialog shows its outcome.
