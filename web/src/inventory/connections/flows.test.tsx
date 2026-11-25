import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi, type MockHandler } from "../../test/fetchMock";
import { ConnectionsPage } from "./ConnectionsPage";
import { ConnectionDetailPage } from "./ConnectionDetailPage";
import { Onboarding, parseTargets } from "./Onboarding";
import { ImpactReview } from "../ui/ImpactReview";
import { ProfileEditor } from "../profiles/ProfileEditor";
import { CredentialEditor } from "../profiles/CredentialEditor";
import { ProfilesPage } from "../profiles/ProfilesPage";
import { materialize } from "./MetadataFields";
import type { CollectorFieldMetadata, ConnectionView, ProfileView, CredentialView, PreviewResponse, TargetView } from "../../api/inventory";
import type { SourceTypeSchema } from "../../api/types";
let permissions = ["runs.manage", "sources.write", "sites.write", "graph.read"];
vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions }, loading: false }) }));
const schema: SourceTypeSchema = { type: "object", properties: { host: { type: "string", title: "Endpoint" }, interval_s: { type: "integer", default: 60 }, routing_scope: { type: "string" }, auth: { oneOf: [{ type: "object", properties: { method: { const: "password" }, username: { type: "string" }, password: { type: "string", format: "password" } }, required: ["username", "password"] }, { type: "object", properties: { method: { const: "key" }, api_key: { type: "string", format: "password" } } }] } } };
const meta = (type: string, kind: "direct" | "controller"): CollectorFieldMetadata => ({ collector_type: type, kind, fields: [
  { path: "host", category: "connection", secret: false, variant: null, identity_sensitivity: "identity", profile_applicability: "", label: "Endpoint" },
  { path: "interval_s", category: "profile", secret: false, variant: null, identity_sensitivity: "none", profile_applicability: "", label: "Interval" },
  { path: "auth.username", category: "profile", secret: false, variant: "UserPassword", identity_sensitivity: "none", profile_applicability: "", label: "Username" },
  { path: "auth.method", category: "profile", secret: false, variant: "UserPassword", identity_sensitivity: "none", profile_applicability: "", label: "Method" },
  { path: "auth.password", category: "credential", secret: true, variant: "UserPassword", identity_sensitivity: "none", profile_applicability: "", label: "Password" },
  { path: "auth.api_key", category: "credential", secret: true, variant: "ApiKey", identity_sensitivity: "none", profile_applicability: "", label: "API key" },
  { path: "routing_scope", category: "legacy_normalization", secret: false, variant: null, identity_sensitivity: "identity", profile_applicability: "", label: "Routing scope" },
] });
const connection: ConnectionView = { id: "c1", name: "controller-key", display_name: "Controller", kind: "controller", collector_type: "ctrl", enabled: false, config: { host: "controller.example" }, profile_id: "p1", revision: 1, frozen_normalization: null, health: { state: "never", last_success_at: null, last_attempt_at: null, failing_targets: 0, target_count: 1, device_count: 0 }, created_at: "", updated_at: "" };
const profile: ProfileView = { id: "p1", display_name: "Standard access", collector_type: "ctrl", current_revision: 2, archived_at: null, credential_id: "secret1", credential_revision: 1, settings: { auth: { method: "password", username: "operator" } }, usage: { targets: 2, connections: 1 }, created_at: "", updated_at: "" };
const credential: CredentialView = { id: "secret1", display_name: "SSH access", current_revision: 1, secret_paths: ["auth.password"], archived_at: null, profiles_using: 1, created_at: "", updated_at: "" };
const target: TargetView = { id: "t1", connection_id: "c1", source_key: connection.name, host: "controller.example", port: null, kind: "controller", enabled: false, host_key_pinned: false, profile_id: null, onboarding_site_id: null, legacy_device_id: null, revision: 1, archived_at: null, observed_device_ids: [], last_attempt_at: null, last_success_at: null, consecutive_failures: 0, last_error: "" };
const preview: PreviewResponse = { token: "preview1", operation: "edit_profile", expires_at: new Date(Date.now() + 600000).toISOString(), generation: { snapshot_key: "snap", intent_generation: 1, inventory_sync_pending: false }, members: [{ kind: "profile", id: "p1", revision: 2, label: "Standard access" }], member_count: 1, affected_device_count: 2, affected_target_count: 1, changes: { settings: "changed" }, warnings: [] };
function routes(overrides: Record<string, MockHandler> = {}) { mockApi({
  "GET /api/source-types": () => ({ body: { types: ["ctrl", "ssh"].map(type => ({ type, schema })) } }),
  "GET /api/inventory/field-metadata": () => ({ body: [meta("ctrl", "controller"), meta("ssh", "direct")] }),
  "GET /api/inventory/connections": () => ({ body: [connection] }),
  "GET /api/inventory/connections/c1": () => ({ body: connection }),
  "GET /api/inventory/profiles": () => ({ body: [profile, { ...profile, id: "p2", collector_type: "ssh", display_name: "SSH profile" }] }),
  "GET /api/inventory/credentials": () => ({ body: [credential] }),
  "GET /api/inventory/sites": () => ({ body: [] }),
  "GET /api/inventory/targets": () => ({ body: [target] }),
  "GET /api/inventory/locations": () => ({ body: [] }),
  "POST /api/inventory/operations/preview": () => ({ body: preview }),
  "GET /api/inventory/operations/previews/preview1/impact": () => ({ body: { items: [], total: 0, next_cursor: null, generation: preview.generation } }), ...overrides }); }
function mount(child: React.ReactNode, entry = "/inventory/connections") { const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><Routes><Route path="/inventory/connections" element={child} /><Route path="/inventory/connections/c1" element={<p>Saved connection detail</p>} /><Route path="/detail/:id" element={child} /><Route path="/inventory/connections/profiles" element={child} /></Routes></MemoryRouter></QueryClientProvider>); return client; }
beforeEach(() => { permissions = ["runs.manage", "sources.write", "sites.write", "graph.read"]; });
describe("inventory connection flows", () => {
  it("onboards a controller as disabled with profile reuse and no automatic probe", async () => {
    const user = userEvent.setup(); const create = vi.fn((_req: any) => ({ body: connection })); routes({ "POST /api/inventory/connections": create }); mount(<Onboarding onCancel={() => {}} />);
    await user.selectOptions(screen.getByLabelText("Onboarding type"), "controller"); await waitFor(() => expect(screen.getByRole("option", { name: "ctrl" })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText("Collector type"), "ctrl"); await user.type(screen.getByLabelText("Source key"), "new-controller"); await user.type(screen.getByLabelText("Endpoint"), "controller.example"); await user.selectOptions(screen.getByLabelText("Collection profile"), "p1");
    expect(screen.queryByLabelText(/Routing scope/)).not.toBeInTheDocument(); expect(screen.queryByLabelText(/Password/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Preview onboarding" })); await user.click(await screen.findByRole("button", { name: "Save reviewed onboarding" })); await screen.findByText("Saved connection detail");
    expect(create.mock.calls[0][0].body).toMatchObject({ name: "new-controller", enabled: false, profile_id: "p1", config: { host: "controller.example" } });
    expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes("probe"))).toBe(false);
  });
  it("retains direct drafts after partial failure and retries only remaining targets", async () => {
    const user = userEvent.setup(); let attempts = 0; const create = vi.fn(() => ({ body: { ...connection, kind: "direct", collector_type: "ssh" } })); const add = vi.fn((req: any) => ++attempts === 2 ? { status: 422, body: { error: "bad second host" } } : { body: { ...target, ...req.body } });
    routes({ "POST /api/inventory/connections": create, "POST /api/inventory/targets": add }); mount(<Onboarding onCancel={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "ssh" })).toBeInTheDocument()); await user.selectOptions(screen.getByLabelText("Collector type"), "ssh"); await user.type(screen.getByLabelText("Source key"), "routers"); await user.selectOptions(screen.getByLabelText("Collection profile"), "p2"); await user.type(screen.getByLabelText("Hosts and optional ports"), "r1 22\nr2,2222");
    await user.click(screen.getByRole("button", { name: "Preview onboarding" })); await user.click(await screen.findByRole("button", { name: "Save reviewed onboarding" })); await screen.findByText("bad second host"); expect(screen.getByLabelText("Hosts and optional ports")).toHaveValue("r1 22\nr2,2222");
    await user.clear(screen.getByLabelText("Remaining target rows")); await user.type(screen.getByLabelText("Remaining target rows"), "r3 2222"); await user.click(screen.getByRole("button", { name: "Update remaining target draft" })); await user.click(screen.getByRole("button", { name: "Save reviewed onboarding" })); await screen.findByText("Saved connection detail"); expect(create).toHaveBeenCalledTimes(1); expect(add.mock.calls.map(([req]) => req.body.host)).toEqual(["r1", "r2", "r3"]);
  });
  it("preserves onboarding when creating an inline profile", async () => {
    const user = userEvent.setup(); const save = vi.fn((_req: any) => ({ body: { ...profile, id: "new-profile", collector_type: "ssh" } })); routes({ "POST /api/inventory/profiles": save }); mount(<Onboarding onCancel={() => {}} />);
    await waitFor(() => expect(screen.getByRole("option", { name: "ssh" })).toBeInTheDocument()); await user.selectOptions(screen.getByLabelText("Collector type"), "ssh"); await user.type(screen.getByLabelText("Source key"), "preserved"); await user.type(screen.getByLabelText("Hosts and optional ports"), "r1"); await user.click(screen.getByRole("button", { name: "Create profile inline" }));
    await user.type(await screen.findByLabelText("Profile name"), "Inline"); await user.type(screen.getByLabelText("Username"), "alice"); await user.click(screen.getByRole("button", { name: "Save profile" })); await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText("Source key")).toHaveValue("preserved"); expect(screen.getByLabelText("Hosts and optional ports")).toHaveValue("r1"); expect(save.mock.calls[0][0].body.settings).toEqual({ interval_s: 60, auth: { method: "password", username: "alice" } });
  });
  it("applies after one confirmation, recalculates a stale preview and keeps the idempotency key on a network retry", async () => {
    const user = userEvent.setup(); let applies = 0; const previewCall = vi.fn((_req: any) => ({ body: preview }));
    const apply = vi.fn((_req: any) => ++applies === 1 ? { status: 409, body: { error: "stale revision" } } : applies === 2 ? { status: 503, body: { error: "temporary" } } : { body: { status: "applied" } });
    const done = vi.fn();
    routes({ "POST /api/inventory/operations/preview": previewCall, "POST /api/inventory/operations/apply": apply });
    mount(<ImpactReview request={{ operation: "edit_profile", selection: { ids: ["p1"] } }} onDone={done} onCancel={() => {}} />);
    await waitFor(() => expect(previewCall).toHaveBeenCalledTimes(1)); expect(apply).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("button", { name: "Apply" })); await screen.findByText(/Inventory changed after the preview/); expect(previewCall).toHaveBeenCalledTimes(2);
    await user.click(screen.getByRole("button", { name: "Apply" })); await screen.findByText("temporary");
    await user.click(screen.getByRole("button", { name: "Apply" })); await waitFor(() => expect(done).toHaveBeenCalled());
    expect(apply.mock.calls[1][0].body.idempotency_key).toEqual(apply.mock.calls[2][0].body.idempotency_key);
    expect(apply.mock.calls[0][0].body.idempotency_key).not.toEqual(apply.mock.calls[1][0].body.idempotency_key);
  });
  it("rotates write-only credentials without plaintext in query or mutation cache", async () => {
    const user = userEvent.setup(); const captured = vi.fn((_req: any) => ({ body: { ...preview, operation: "rotate_credential", changes: { secrets: "***" } } })); routes({ "POST /api/inventory/operations/preview": captured }); const client = mount(<CredentialEditor collectorType="ctrl" credential={credential} onSaved={() => {}} onCancel={() => {}} />);
    const password = await screen.findByLabelText("Password"); expect(password).toHaveValue(""); expect(password).toHaveAttribute("type", "password"); await user.type(password, "super-secret"); await user.click(screen.getByRole("button", { name: "Preview credential rotation" })); await screen.findByText("No other affected records"); expect(captured.mock.calls[0][0].body.change.secrets).toEqual({ "auth.password": "super-secret" }); expect(JSON.stringify(client.getQueryCache().getAll().map(q => q.state.data))).not.toContain("super-secret"); expect(client.getMutationCache().getAll()).toHaveLength(0);
  });
  it("previews profile edits with their expected revision", async () => {
    const user = userEvent.setup(); const captured = vi.fn((_req: any) => ({ body: preview })); routes({ "POST /api/inventory/operations/preview": captured }); mount(<ProfileEditor collectorType="ctrl" profile={profile} onSaved={() => {}} onCancel={() => {}} />); await user.clear(await screen.findByLabelText("Profile name")); await user.type(screen.getByLabelText("Profile name"), "Updated"); await user.click(screen.getByRole("button", { name: "Preview profile changes" })); await waitFor(() => expect(captured).toHaveBeenCalled()); expect(captured.mock.calls[0][0].body).toMatchObject({ operation: "edit_profile", change: { display_name: "Updated", expected_revision: 2, credential_id: "secret1" } });
  });
  it("allows operator probes of disabled drafts while hiding configuration writes", async () => {
    permissions = ["runs.manage", "graph.read"]; const user = userEvent.setup(); const probe = vi.fn(() => ({ body: { ok: false, message: "Authentication failed", duration_ms: 10, effective: { profile_revision: 2, credential_revision: 1 } } })); routes({ "POST /api/inventory/targets/t1/probe": probe }); mount(<ConnectionDetailPage />, "/detail/c1"); await user.click(await screen.findByRole("button", { name: "Probe stored configuration" })); await screen.findByText("Probe failed: Authentication failed"); expect(screen.queryByRole("button", { name: "Edit connection" })).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: "Enable target" })).not.toBeInTheDocument(); expect(screen.getByRole("button", { name: "Collect connection once" })).toBeDisabled(); expect(probe).toHaveBeenCalledTimes(1);
  });
  it("does not fetch connection internals for viewers", () => { permissions = ["graph.read"]; routes(); mount(<ConnectionsPage />); expect(screen.getByText("No runs.manage permission")).toBeInTheDocument(); expect(fetch).not.toHaveBeenCalled(); });
  it("uses explicit target IDs handed off from devices for profile assignment", async () => {
    const user = userEvent.setup(); const captured = vi.fn((_req: any) => ({ body: preview })); routes({ "POST /api/inventory/operations/preview": captured }); mount(<ProfilesPage />, "/inventory/connections/profiles?target_id=t1"); await waitFor(() => expect(screen.getByRole("checkbox")).toBeChecked()); await user.selectOptions(screen.getByLabelText("Assign profile"), "p1"); await user.click(screen.getByRole("button", { name: "Preview target assignment" })); await waitFor(() => expect(captured).toHaveBeenCalled()); expect(captured.mock.calls[0][0].body).toEqual({ operation: "assign_target_profile", selection: { ids: ["t1"] }, change: { profile_id: "p1" } });
  });
  it("validates pasted hosts and preserves IPv6 identity and classified auth fields", () => { expect(parseTargets("2001:db8::1 2222\nrouter.example")).toEqual([{ host: "2001:db8::1", port: 2222 }, { host: "router.example" }]); expect(() => parseTargets("router 22\nrouter 23")).toThrow("duplicate host"); expect(() => parseTargets("router 65536")).toThrow("port outside"); expect(() => parseTargets("https://router")).toThrow("hostname or IP"); expect(materialize(schema, meta("ctrl", "controller"), "profile", { auth: { method: "key", api_key: "secret" }, routing_scope: "bad" })).toEqual({ interval_s: 60, auth: { method: "key" } }); });
});
