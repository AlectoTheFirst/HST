import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SchemaForm } from "./SchemaForm";
import { SCHEMA_MANUAL, SCHEMA_UNIFI, SOURCE_UNIFI } from "../test/fixtures";
import fixtures from "./schema.fixtures.json";

const APIC_SCHEMA = fixtures.apic;            // nested models, no union
const CP_SCHEMA = fixtures.checkpoint;        // oneOf + discriminator union
const NXOS_SCHEMA = fixtures.nxos;            // three-way union + optional nested jump_host (its own three-way union)

describe("SchemaForm: write-only secrets", () => {
  it("renders the password field blank on edit when the field has a stored value", () => {
    render(
      <SchemaForm
        schema={SCHEMA_UNIFI}
        config={SOURCE_UNIFI.config}
        mode="edit"
        submitLabel="Save"
        onSubmit={vi.fn()}
      />,
    );

    const password = screen.getByLabelText("Password") as HTMLInputElement;
    expect(password).toHaveAttribute("type", "password");
    expect(password.value).toBe("");
    expect(password).not.toBeRequired();
  });

  it("omits the untouched secret from the submitted config, but includes changed non-secret fields", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm
        schema={SCHEMA_UNIFI}
        config={SOURCE_UNIFI.config}
        mode="edit"
        submitLabel="Save"
        onSubmit={onSubmit}
      />,
    );

    const site = screen.getByLabelText("Site") as HTMLInputElement;
    expect(site.value).toBe("default"); // prefilled from `config`
    await user.clear(site);
    await user.type(site, "backup");

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted).not.toHaveProperty("password");
    expect(submitted.site).toBe("backup");
    expect(submitted.url).toBe(SOURCE_UNIFI.config.url);
    expect(submitted.verify_ssl).toBe(false);
  });

  it("includes a typed secret", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm
        schema={SCHEMA_UNIFI}
        config={SOURCE_UNIFI.config}
        mode="edit"
        submitLabel="Save"
        onSubmit={onSubmit}
      />,
    );

    await user.type(screen.getByLabelText("Password"), "new-secret");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(onSubmit.mock.calls[0][0].password).toBe("new-secret");
  });

  it("marks the password required on create", () => {
    render(
      <SchemaForm schema={SCHEMA_UNIFI} mode="create" submitLabel="Create" onSubmit={vi.fn()} />,
    );

    // the label of a required field ends in " *"
    const password = screen.getByLabelText("Password", { exact: false });
    expect(password).toBeRequired();
    expect(password).toHaveAttribute("id", "sf-password");
  });

  it("excludes source_name from the rendered form", () => {
    render(
      <SchemaForm schema={SCHEMA_UNIFI} mode="create" submitLabel="Create" onSubmit={vi.fn()} />,
    );

    expect(screen.queryByLabelText(/source name/i)).not.toBeInTheDocument();
  });

  it("disables the submit button while pending", () => {
    render(
      <SchemaForm schema={SCHEMA_UNIFI} mode="create" submitLabel="Create" pending onSubmit={vi.fn()} />,
    );

    expect(screen.getByRole("button", { name: /saving/i })).toBeDisabled();
  });
});

describe("SchemaForm: format \"multiline\" renders a textarea", () => {
  it("round-trips a multi-line value into the submitted config", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm schema={SCHEMA_MANUAL} mode="create" submitLabel="Create" onSubmit={onSubmit} />,
    );

    const devices = screen.getByLabelText("Devices", { exact: false });
    expect(devices.tagName).toBe("TEXTAREA");

    const pasted = "edge-r1, 10.0.0.1, nxos, router, FDO12345\nedge-r2, 10.0.0.2, iosxe, router";
    await user.type(devices, pasted);
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit.mock.calls[0][0].devices).toBe(pasted);
  });
});

describe("SchemaForm: nested and either-or credentials", () => {
  it("renders fields from a nested model", () => {
    render(<SchemaForm schema={APIC_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });

  it("never renders the method discriminator as an editable field", () => {
    render(<SchemaForm schema={APIC_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);
    expect(screen.queryByRole("textbox", { name: /method/i })).not.toBeInTheDocument();
  });

  it("submits nested values as a nested object carrying the method literal", async () => {
    const onSubmit = vi.fn();
    render(<SchemaForm schema={APIC_SCHEMA} mode="create" submitLabel="Save" onSubmit={onSubmit} />);
    await userEvent.type(screen.getByLabelText(/url/i), "https://apic");
    await userEvent.type(screen.getByLabelText(/fabric/i), "f1");
    await userEvent.type(screen.getByLabelText(/username/i), "admin");
    await userEvent.type(screen.getByLabelText(/password/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      url: "https://apic",
      auth: { method: "user_password", username: "admin", password: "pw" },
    }));
  });

  it("omits a blank nested secret so the stored value survives a PATCH", async () => {
    const onSubmit = vi.fn();
    render(
      <SchemaForm schema={APIC_SCHEMA} mode="edit" submitLabel="Save" onSubmit={onSubmit}
                  config={{ url: "https://apic", fabric: "f1",
                            auth: { method: "user_password", username: "admin" } }} />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted.auth).toEqual({ method: "user_password", username: "admin" });
  });

  it("offers a method selector for a union and renders only the chosen variant", async () => {
    // TlsConfig's optional client_cert block also has a field labelled "Key".
    render(<SchemaForm schema={CP_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);
    expect(document.getElementById("sf-auth.key")).not.toBeNull();
    expect(screen.queryByLabelText(/username/i)).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText(/auth method/i), "user_password");
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(document.getElementById("sf-auth.key")).toBeNull();
  });

  it("initialises the selector from the stored method when editing", () => {
    render(<SchemaForm schema={CP_SCHEMA} mode="edit" submitLabel="Save" onSubmit={vi.fn()}
                       config={{ host: "cp1",
                                 auth: { method: "user_password", username: "admin" } }} />);
    expect(screen.getByLabelText(/auth method/i)).toHaveValue("user_password");
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
  });

  it("drops the previous variant's values when the method switches", async () => {
    const onSubmit = vi.fn();
    render(<SchemaForm schema={CP_SCHEMA} mode="create" submitLabel="Save" onSubmit={onSubmit} />);
    await userEvent.type(screen.getByLabelText(/host/i), "cp1");
    await userEvent.type(document.getElementById("sf-auth.key") as HTMLInputElement, "old-key");
    await userEvent.selectOptions(screen.getByLabelText(/auth method/i), "user_password");
    await userEvent.type(screen.getByLabelText(/username/i), "admin");
    await userEvent.type(screen.getByLabelText(/password/i), "pw");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted.auth).toEqual({ method: "user_password", username: "admin", password: "pw" });
    expect(JSON.stringify(submitted)).not.toContain("old-key");
  });
});

describe("SchemaForm: three-way ssh union and optional jump host", () => {
  // The host and the jump host share field labels.

  it("offers a three-way ssh auth selector: password, private key, or agent", () => {
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);

    expect(document.querySelector('label[for="sf-auth-method"]')?.textContent).toMatch(/auth method/i);
    const hostAuthSelect = document.getElementById("sf-auth-method") as HTMLSelectElement;
    const methods = Array.from(hostAuthSelect.options).map((o) => o.value);
    expect(methods).toEqual(["password", "private_key", "agent"]);
  });

  it("selecting agent for the host's own auth renders only a username, with no secret field", async () => {
    const user = userEvent.setup();
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);

    await user.selectOptions(document.getElementById("sf-auth-method") as HTMLSelectElement, "agent");

    expect(document.getElementById("sf-auth.username")).not.toBeNull();
    expect(document.querySelector('label[for="sf-auth.username"]')?.textContent).toMatch(/username/i);

    // SshAgent has no secret fields.
    expect(document.getElementById("sf-auth.password")).toBeNull();
    expect(document.getElementById("sf-auth.private_key")).toBeNull();
    expect(document.getElementById("sf-auth.passphrase")).toBeNull();
  });

  it("drops private_key/passphrase from the submitted config after switching the host's auth to agent", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={onSubmit} />);

    await user.type(document.getElementById("sf-host") as HTMLInputElement, "sw1");
    await user.type(document.getElementById("sf-auth.username") as HTMLInputElement, "admin");
    await user.type(document.getElementById("sf-auth.password") as HTMLInputElement, "old-pw");

    await user.selectOptions(document.getElementById("sf-auth-method") as HTMLSelectElement, "private_key");
    await user.type(document.getElementById("sf-auth.private_key") as HTMLInputElement, "old-key-material");
    await user.type(document.getElementById("sf-auth.passphrase") as HTMLInputElement, "old-pass-phrase");

    await user.selectOptions(document.getElementById("sf-auth-method") as HTMLSelectElement, "agent");

    await user.click(screen.getByRole("button", { name: "Save" }));

    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted.auth).toEqual({ method: "agent", username: "admin" });
    expect(JSON.stringify(submitted.auth)).not.toMatch(/old-(pw|key-material|pass-phrase)/);
  });

  it("omits jump_host from the submitted config when no jump host field is touched", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={onSubmit} />);

    await user.type(document.getElementById("sf-host") as HTMLInputElement, "sw1");
    await user.type(document.getElementById("sf-auth.username") as HTMLInputElement, "admin");
    await user.type(document.getElementById("sf-auth.password") as HTMLInputElement, "pw");

    await user.click(screen.getByRole("button", { name: "Save" }));

    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted).not.toHaveProperty("jump_host");
  });

  it("submits jump_host as a nested object with its own auth method once the bastion is configured", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={onSubmit} />);

    await user.type(document.getElementById("sf-host") as HTMLInputElement, "sw1");
    await user.type(document.getElementById("sf-auth.username") as HTMLInputElement, "admin");
    await user.type(document.getElementById("sf-auth.password") as HTMLInputElement, "pw");

    await user.type(document.getElementById("sf-jump_host.host") as HTMLInputElement, "bastion1");
    await user.selectOptions(document.getElementById("sf-jump_host.auth-method") as HTMLSelectElement, "agent");
    await user.type(document.getElementById("sf-jump_host.auth.username") as HTMLInputElement, "bastion-user");

    await user.click(screen.getByRole("button", { name: "Save" }));

    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted.host).toBe("sw1");
    expect(submitted.jump_host).toEqual({
      host: "bastion1",
      port: 22,
      host_key: "",
      auth: { method: "agent", username: "bastion-user" },
    });
  });
});

describe("SchemaForm: empty optional numerics are omitted", () => {
  const NUMERIC_SCHEMA = {
    type: "object",
    title: "NumericConfig",
    properties: {
      host: { type: "string", title: "Host" },
      port: { type: "integer", title: "Port" },
      timeout: { type: "number", title: "Timeout" },
    },
    required: ["host"],
  };

  it("leaves untouched optional numeric fields out of the submission", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm schema={NUMERIC_SCHEMA} mode="create" submitLabel="Create" onSubmit={onSubmit} />,
    );

    await user.type(screen.getByLabelText("Host", { exact: false }), "sw1");
    await user.click(screen.getByRole("button", { name: "Create" }));

    const submitted = onSubmit.mock.calls[0][0];
    expect(submitted.host).toBe("sw1");
    // Number("") is 0
    expect(submitted).not.toHaveProperty("port");
    expect(submitted).not.toHaveProperty("timeout");
  });

  it("still submits an explicit 0", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm schema={NUMERIC_SCHEMA} mode="create" submitLabel="Create" onSubmit={onSubmit} />,
    );

    await user.type(screen.getByLabelText("Host", { exact: false }), "sw1");
    await user.type(screen.getByLabelText("Timeout", { exact: false }), "0");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(onSubmit.mock.calls[0][0].timeout).toBe(0);
  });

  it("submits a typed numeric value as a number", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(
      <SchemaForm schema={NUMERIC_SCHEMA} mode="create" submitLabel="Create" onSubmit={onSubmit} />,
    );

    await user.type(screen.getByLabelText("Host", { exact: false }), "sw1");
    await user.type(screen.getByLabelText("Port", { exact: false }), "8443");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(onSubmit.mock.calls[0][0].port).toBe(8443);
  });
});

describe("SchemaForm: nested blocks are grouped", () => {
  it("puts the jump host in a labelled fieldset", () => {
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);

    const group = screen.getByRole("group", { name: /jump host/i });
    expect(group).toBeInTheDocument();
    expect(group).toHaveTextContent(/optional/i);
  });

  it("keeps the bastion's fields inside the group and the device's outside it", () => {
    render(<SchemaForm schema={NXOS_SCHEMA} mode="create" submitLabel="Save" onSubmit={vi.fn()} />);

    const group = screen.getByRole("group", { name: /jump host/i });
    expect(group).toContainElement(document.getElementById("sf-jump_host.host"));
    expect(group).toContainElement(document.getElementById("sf-jump_host.port"));
    expect(group).not.toContainElement(document.getElementById("sf-host"));
    expect(group).not.toContainElement(document.getElementById("sf-password"));
  });
});
