// @ts-expect-error -- Vitest runs in Node; browser tsconfig excludes Node module declarations.
import { generateKeyPairSync } from "node:crypto";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { CollectorFieldMetadata, CredentialView } from "../../api/inventory";
import { mockApi, type MockRequest } from "../../test/fetchMock";
import { CredentialEditor } from "./CredentialEditor";

vi.mock("../../auth", () => ({ useAuth: () => ({ user: { permissions: ["sources.write"] } }) }));

const { privateKey: key }: { privateKey: string } = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

describe("credential private key entry", () => {
  it.each(["auth.private_key", "jump_host.auth.private_key", "tls.client_cert.key"])(
    "preserves pasted line breaks in %s and keeps tokens masked",
    async path => {
      const user = userEvent.setup();
      const metadata: CollectorFieldMetadata = {
        collector_type: "velocloud", kind: "controller",
        fields: [path, "auth.key"].map(path => ({
          path, variant: null, category: "credential", secret: true,
          identity_sensitivity: "none", profile_applicability: "velocloud", label: path,
        })),
      };
      const credential: CredentialView = {
        id: "c1", display_name: "VCO access", current_revision: 1,
        secret_paths: [path, "auth.key"], archived_at: null, profiles_using: 0,
        created_at: "", updated_at: "",
      };
      const save = vi.fn((_request: MockRequest) => ({ body: credential }));
      mockApi({
        "GET /api/inventory/field-metadata": () => ({ body: [metadata] }),
        "GET /api/source-types": () => ({ body: { types: [] } }),
        "POST /api/inventory/credentials": save,
      });
      const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(<QueryClientProvider client={client}>
        <CredentialEditor collectorType="velocloud" onSaved={() => {}} onCancel={() => {}} />
      </QueryClientProvider>);
      const input = await screen.findByLabelText(path);
      await user.type(screen.getByLabelText("Credential name"), "VCO access");
      await user.click(input);
      await user.paste(key);
      const token = screen.getByLabelText("auth.key");
      expect(token).toHaveAttribute("type", "password");
      await user.type(token, "vco-token");
      await user.click(screen.getByRole("button", { name: "Save credential" }));
      await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
      expect(save.mock.calls[0][0].body).toEqual({
        display_name: "VCO access", secrets: { [path]: key, "auth.key": "vco-token" },
      });
      await waitFor(() => expect(input).toHaveValue(""));
      expect(token).toHaveValue("");
      expect(JSON.stringify(client.getQueryCache().getAll().map(q => q.state.data))).not.toContain(key.split("\n")[1]);
      expect(client.getMutationCache().getAll()).toHaveLength(0);
    },
  );
});
