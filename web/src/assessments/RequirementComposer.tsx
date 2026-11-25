import { MtuRequirementFields } from "./MtuRequirementFields";
import { useState } from "react";
import type { Condition, Member, Requirement } from "./types";
import { conditionSentence, list } from "./types";

export function Field({
  label,
  value,
  onChange,
  required,
  type = "text",
}: {
  label: string;
  value: string | number;
  onChange: (value: string) => void;
  required?: boolean;
  type?: string;
}) {
  return (
    <label className="assessment-field">
      <span>{label}</span>
      <input
        type={type}
        step={type === "number" ? "any" : undefined}
        value={value}
        required={required}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

export function ListField({
  label,
  value,
  onChange,
  required,
}: {
  label: string;
  value: string[];
  onChange: (value: string[]) => void;
  required?: boolean;
}) {
  const [text, setText] = useState(() => value.join(", "));
  const canonical = value.join(", ");
  const [previous, setPrevious] = useState(canonical);
  if (canonical !== previous) {
    setPrevious(canonical);
    setText(canonical);
  }
  return (
    <Field
      label={label}
      value={text}
      required={required}
      onChange={(next) => {
        const parsed = list(next);
        setText(next);
        setPrevious(parsed.join(", "));
        onChange(parsed);
      }}
    />
  );
}

function ConditionEditor({
  value,
  members,
  onChange,
  depth = 0,
}: {
  value: Condition;
  members: Member[];
  onChange: (value: Condition) => void;
  depth?: number;
}) {
  return (
    <fieldset className="assessment-condition">
      <legend>{depth ? "Condition group" : "Success condition"}</legend>
      <label className="assessment-field">
        <span>Condition type</span>
        <select
          value={value.kind}
          onChange={(e) => {
            const kind = e.target.value as Condition["kind"];
            onChange(
              kind === "member"
                ? { kind, member: members[0]?.name }
                : {
                    kind,
                    ...(kind === "threshold" ? { n: 1 } : {}),
                    parts: value.parts?.length
                      ? value.parts
                      : [{ kind: "member", member: members[0]?.name }],
                  },
            );
          }}
        >
          <option value="member">One member</option>
          <option value="and">All</option>
          <option value="or">Any</option>
          <option value="threshold">At least N</option>
        </select>
      </label>
      {value.kind === "member" ? (
        <label className="assessment-field">
          <span>Required member</span>
          <select
            value={value.member ?? ""}
            onChange={(e) => onChange({ ...value, member: e.target.value })}
          >
            <option value="">Select a member</option>
            {members.map((m, i) => (
              <option key={i} value={m.name}>
                {m.name || `Unnamed member ${i + 1}`}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <>
          {value.kind === "threshold" && (
            <Field
              label="Minimum members or groups"
              type="number"
              value={value.n ?? 1}
              onChange={(n) => onChange({ ...value, n: Number(n) })}
            />
          )}
          {(value.parts ?? []).map((part, i) => (
            <div key={i} className="assessment-condition-part">
              <ConditionEditor
                value={part}
                members={members}
                depth={depth + 1}
                onChange={(next) =>
                  onChange({ ...value, parts: value.parts!.map((p, j) => (i === j ? next : p)) })
                }
              />
              <button
                type="button"
                onClick={() =>
                  onChange({ ...value, parts: value.parts!.filter((_, j) => i !== j) })
                }
              >
                Remove condition {i + 1}
              </button>
            </div>
          ))}
          {depth < 8 && (
            <button
              type="button"
              onClick={() =>
                onChange({
                  ...value,
                  parts: [...(value.parts ?? []), { kind: "member", member: members[0]?.name }],
                })
              }
            >
              Add condition
            </button>
          )}
        </>
      )}
    </fieldset>
  );
}

export function RequirementComposer({
  value,
  onChange,
}: {
  value: Requirement;
  onChange: (value: Requirement) => void;
}) {
  function field(key: keyof Requirement, next: string) {
    onChange({ ...value, [key]: next || null });
  }
  function member(index: number, key: keyof Member, next: string) {
    let condition = value.condition;
    if (key === "name") {
      const rename = (c: Condition): Condition =>
        c.kind === "member"
          ? { ...c, member: c.member === value.members[index].name ? next : c.member }
          : { ...c, parts: c.parts?.map(rename) };
      condition = rename(condition);
    }
    onChange({
      ...value,
      condition,
      members: value.members.map((m, i) =>
        i === index
          ? { ...m, [key]: key === "addresses" ? list(next) : key === "name" ? next : next || null }
          : m,
      ),
    });
  }
  return (
    <div className="assessment-composer">
      <div className="assessment-fields">
        <Field
          label="Requirement name"
          value={value.name}
          required
          onChange={(name) => onChange({ ...value, name })}
        />
        <Field
          label="Logical destination"
          value={value.destination}
          required
          onChange={(destination) => onChange({ ...value, destination })}
        />
        <ListField
          label="Client addresses or prefixes"
          value={value.sources}
          required
          onChange={(sources) => onChange({ ...value, sources })}
        />
      </div>
      <fieldset>
        <legend>Default service</legend>
        <div className="assessment-fields">
          <Field
            label="Default protocol"
            value={value.proto ?? ""}
            onChange={(next) => field("proto", next)}
          />
          <Field
            label="Default destination port"
            value={value.port ?? ""}
            onChange={(next) => field("port", next)}
          />
          <Field
            label="Default source port"
            value={value.source_port ?? ""}
            onChange={(next) => field("source_port", next)}
          />
        </div>
      </fieldset>
      <MtuRequirementFields
        value={value.mtu}
        ipv6={value.sources.some((source) => source.includes(":"))}
        onChange={(mtu) => onChange({ ...value, mtu })}
      />
      {value.members.map((m, i) => (
        <fieldset key={i}>
          <legend>Destination member {i + 1}</legend>
          <div className="assessment-fields">
            <Field
              label={`Member ${i + 1} name`}
              value={m.name}
              required
              onChange={(next) => member(i, "name", next)}
            />
            <ListField
              label={`Member ${i + 1} addresses`}
              value={m.addresses}
              required
              onChange={(next) => member(i, "addresses", next.join(","))}
            />
            <Field
              label={`Member ${i + 1} protocol`}
              value={m.proto ?? ""}
              onChange={(next) => member(i, "proto", next)}
            />
            <Field
              label={`Member ${i + 1} destination port`}
              value={m.port ?? ""}
              onChange={(next) => member(i, "port", next)}
            />
            <Field
              label={`Member ${i + 1} source port`}
              value={m.source_port ?? ""}
              onChange={(next) => member(i, "source_port", next)}
            />
          </div>
          <button
            type="button"
            disabled={value.members.length === 1}
            onClick={() => onChange({ ...value, members: value.members.filter((_, j) => i !== j) })}
          >
            Remove member {i + 1}
          </button>
        </fieldset>
      ))}
      <button
        type="button"
        onClick={() => {
          let n = value.members.length + 1;
          while (value.members.some((m) => m.name === `member-${n}`)) n++;
          onChange({
            ...value,
            members: [...value.members, { name: `member-${n}`, addresses: [] }],
          });
        }}
      >
        Add destination member
      </button>
      <ConditionEditor
        value={value.condition}
        members={value.members}
        onChange={(condition) => onChange({ ...value, condition })}
      />
      <p className="assessment-condition-summary">{conditionSentence(value.condition)}</p>
      <div className="assessment-fields">
        <label className="assessment-field">
          <span>Connectivity success</span>
          <select value={value.success} onChange={(e) => field("success", e.target.value)}>
            <option value="forward">Forward connectivity</option>
            <option value="round-trip">Round trip</option>
            <option value="session">Session</option>
          </select>
        </label>
      </div>
      <details>
        <summary>VRF, device and identity context</summary>
        <div className="assessment-fields">
          <Field
            label="Source VRF / context UID"
            value={value.source_context ?? ""}
            onChange={(next) => field("source_context", next)}
          />
          <Field
            label="Source device UID"
            value={value.source_device_uid ?? ""}
            onChange={(next) => field("source_device_uid", next)}
          />
          <Field
            label="Identity UID"
            value={value.identity_uid ?? ""}
            onChange={(next) => field("identity_uid", next)}
          />
          <Field
            label="Segment UID"
            value={value.segment_uid ?? ""}
            onChange={(next) => field("segment_uid", next)}
          />
        </div>
      </details>
    </div>
  );
}
