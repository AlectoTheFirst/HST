import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { IntentEditor } from "./IntentEditor";
import type { Intent } from "./types";

function Editor({ initial }: { initial: Intent[] }) {
  const [value, setValue] = useState<Intent[]>(initial);
  return (
    <>
      <IntentEditor value={value} onChange={setValue} />
      <output data-testid="intents">{JSON.stringify(value)}</output>
    </>
  );
}

describe("IntentEditor interface.set_mtu", () => {
  it("switches to interface.set_mtu and edits interface, mtu and the optional address family", async () => {
    const user = userEvent.setup();
    render(
      <Editor
        initial={[{ kind: "fw_rule.add", params: { rulebase: "", action: "accept", position: 0 } }]}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Operation"), "Set interface MTU");
    expect(JSON.parse(screen.getByTestId("intents").textContent!)).toEqual([
      { kind: "interface.set_mtu", params: { interface: "", mtu: 1500 } },
    ]);

    await user.type(screen.getByLabelText("Change 1 interface UID"), "if:eth0.10");
    await user.clear(screen.getByLabelText("Change 1 MTU bytes"));
    await user.type(screen.getByLabelText("Change 1 MTU bytes"), "9000");
    await user.type(screen.getByLabelText("Change 1 address family"), "4");

    expect(JSON.parse(screen.getByTestId("intents").textContent!)).toEqual([
      { kind: "interface.set_mtu", params: { interface: "if:eth0.10", mtu: 9000, af: "4" } },
    ]);
  });

  it("offers only the interface and mtu fields, never the firewall-only ones", () => {
    render(
      <Editor initial={[{ kind: "interface.set_mtu", params: { interface: "if:eth0", mtu: 9000 } }]} />,
    );
    expect(screen.queryByLabelText(/rulebase UID/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/rule UID/)).not.toBeInTheDocument();
    expect(screen.queryByText("Rule action")).not.toBeInTheDocument();
  });
});
