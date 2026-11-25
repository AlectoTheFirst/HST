import type { Intent } from "./types";
import { Field, ListField } from "./RequirementComposer";

export function IntentEditor({
  value,
  onChange,
}: {
  value: Intent[];
  onChange: (value: Intent[]) => void;
}) {
  function change(index: number, key: string, next: unknown) {
    onChange(
      value.map((intent, i) => {
        if (i !== index) return intent;
        const params = { ...intent.params, [key]: next };
        if (key === "action" && next === "") delete params.action;
        if (key === "af" && !next) delete params.af;
        return { ...intent, params };
      }),
    );
  }
  function move(index: number, direction: number) {
    const next = [...value];
    [next[index], next[index + direction]] = [next[index + direction], next[index]];
    onChange(next);
  }
  return (
    <section aria-label="Ordered firewall intents">
      <h3>Proposed firewall changes</h3>
      {value.length === 0 && <p>No changes</p>}
      {value.map((intent, i) => {
        const isMtu = intent.kind === "interface.set_mtu";
        return (
          <fieldset key={i}>
            <legend>Change {i + 1}</legend>
            <div className="assessment-fields">
              <label className="assessment-field">
                <span>Operation</span>
                <select
                  value={intent.kind}
                  onChange={(e) =>
                    onChange(
                      value.map((v, j) => {
                        if (i !== j) return v;
                        if (e.target.value === "interface.set_mtu")
                          return { kind: e.target.value, params: { interface: "", mtu: 1500 } };
                        return {
                          kind: e.target.value,
                          params: {
                            rulebase: v.params.rulebase ?? "",
                            ...(e.target.value === "fw_rule.add"
                              ? { action: "accept", position: 0 }
                              : { rule: "" }),
                          },
                        };
                      }),
                    )
                  }
                >
                  <option value="fw_rule.add">Add firewall rule</option>
                  <option value="fw_rule.modify">Modify firewall rule</option>
                  <option value="fw_rule.remove">Remove firewall rule</option>
                  <option value="interface.set_mtu">Set interface MTU</option>
                  {![
                    "fw_rule.add",
                    "fw_rule.modify",
                    "fw_rule.remove",
                    "interface.set_mtu",
                  ].includes(intent.kind) && <option value={intent.kind}>{intent.kind}</option>}
                </select>
              </label>
              {isMtu ? (
                <>
                  <Field
                    label={`Change ${i + 1} interface UID`}
                    required
                    value={String(intent.params.interface ?? "")}
                    onChange={(v) => change(i, "interface", v)}
                  />
                  <Field
                    label={`Change ${i + 1} MTU bytes`}
                    type="number"
                    required
                    value={Number(intent.params.mtu ?? 0)}
                    onChange={(v) => change(i, "mtu", Number(v))}
                  />
                  <Field
                    label={`Change ${i + 1} address family`}
                    value={String(intent.params.af ?? "")}
                    onChange={(v) => change(i, "af", v)}
                  />
                </>
              ) : (
                <>
                  <Field
                    label={`Change ${i + 1} rulebase UID`}
                    required
                    value={String(intent.params.rulebase ?? "")}
                    onChange={(v) => change(i, "rulebase", v)}
                  />
                  {intent.kind !== "fw_rule.add" && (
                    <Field
                      label={`Change ${i + 1} rule UID`}
                      required
                      value={String(intent.params.rule ?? "")}
                      onChange={(v) => change(i, "rule", v)}
                    />
                  )}
                  {intent.kind === "fw_rule.add" && (
                    <Field
                      label={`Change ${i + 1} insertion position`}
                      type="number"
                      value={Number(intent.params.position ?? 0)}
                      onChange={(v) => change(i, "position", Number(v))}
                    />
                  )}
                  {intent.kind !== "fw_rule.remove" && (
                    <>
                      <label className="assessment-field">
                        <span>Rule action</span>
                        <select
                          value={String(intent.params.action ?? "")}
                          onChange={(e) => change(i, "action", e.target.value)}
                        >
                          {intent.kind === "fw_rule.modify" && (
                            <option value="">Keep collected action</option>
                          )}
                          <option value="accept">Accept</option>
                          <option value="drop">Drop</option>
                          <option value="reject">Reject</option>
                        </select>
                      </label>
                      <ListField
                        label={`Change ${i + 1} source addresses`}
                        value={
                          Array.isArray(intent.params.source)
                            ? (intent.params.source as string[])
                            : []
                        }
                        onChange={(v) => change(i, "source", v)}
                      />
                      <ListField
                        label={`Change ${i + 1} destination addresses`}
                        value={
                          Array.isArray(intent.params.destination)
                            ? (intent.params.destination as string[])
                            : []
                        }
                        onChange={(v) => change(i, "destination", v)}
                      />
                      <ListField
                        label={`Change ${i + 1} protocols`}
                        value={
                          Array.isArray(intent.params.protocols)
                            ? (intent.params.protocols as string[])
                            : []
                        }
                        onChange={(v) => change(i, "protocols", v)}
                      />
                      <ListField
                        label={`Change ${i + 1} ports`}
                        value={
                          Array.isArray(intent.params.ports)
                            ? (intent.params.ports as string[])
                            : []
                        }
                        onChange={(v) => change(i, "ports", v)}
                      />
                    </>
                  )}
                </>
              )}
            </div>
            <div className="assessment-actions">
              <button type="button" disabled={i === 0} onClick={() => move(i, -1)}>
                Move change {i + 1} up
              </button>
              <button type="button" disabled={i === value.length - 1} onClick={() => move(i, 1)}>
                Move change {i + 1} down
              </button>
              <button type="button" onClick={() => onChange(value.filter((_, j) => i !== j))}>
                Remove change {i + 1}
              </button>
            </div>
          </fieldset>
        );
      })}
      <button
        type="button"
        onClick={() =>
          onChange([
            ...value,
            { kind: "fw_rule.add", params: { rulebase: "", action: "accept", position: 0 } },
          ])
        }
      >
        Add firewall change
      </button>
    </section>
  );
}
