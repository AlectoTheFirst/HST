import { useId, useState } from "react";
import type { CollectorFieldMetadata, FieldCategory } from "../../api/inventory";
import type { SourceTypeField, SourceTypeSchema } from "../../api/types";
import { SitePicker } from "../ui/SitePicker";
import { humanize } from "../ui/format";

type Node = SourceTypeField & { $defs?: Record<string, Node>; items?: Node };
type Value = Record<string, unknown>;
export function getPath(value: Value, path: string): unknown { return path.split(".").reduce<unknown>((current, key) => current && typeof current === "object" ? (current as Value)[key] : undefined, value); }
export function setPath(value: Value, path: string, next: unknown): Value {
  const [head, ...tail] = path.split(".");
  const result = { ...value };
  if (!tail.length) { if (next === undefined) delete result[head]; else result[head] = next; }
  else result[head] = setPath((value[head] as Value) ?? {}, tail.join("."), next);
  return result;
}
function resolve(node: Node, root: Node): Node { return node.$ref ? resolve(root.$defs?.[node.$ref.split("/").pop()!] ?? {}, root) : node.allOf?.length === 1 ? resolve(node.allOf[0], root) : node; }
function allowed(path: string, metadata: CollectorFieldMetadata, category: FieldCategory) { if (category === "target" && path === "host_key") return false; return metadata.fields.some(f => f.category === category && (f.path === path || f.path.startsWith(`${path}.`))); }

/** A secret, routing normalization or internal field is never rendered. */
export function MetadataFields({ schema, metadata, category, value, onChange, editing = false, markIdentity = editing }: {
  schema: SourceTypeSchema; metadata: CollectorFieldMetadata; category: FieldCategory; value: Value; onChange: (value: Value) => void; editing?: boolean;
  /** Mark the fields that key the source identity: the edit and the replacement forms. */
  markIdentity?: boolean;
}) {
  const id = useId();
  const root = schema as Node;
  function walk(raw: Node, path: string, required = false): React.ReactNode {
    const node = resolve(raw, root);
    if (path && !allowed(path, metadata, category)) return null;
    const current = path ? getPath(value, path) : value;
    const variants = (node.oneOf ?? node.anyOf)?.filter(v => v.type !== "null").map(v => resolve(v, root));
    if (variants?.length) {
      const method = current && typeof current === "object" ? (current as Value).method : undefined;
      const chosen = variants.find(v => v.properties?.method?.const === method) ?? variants[0];
      const optional = node.anyOf?.some(v => v.type === "null");
      if (variants.length === 1 && !chosen.properties) {
        return walk({ ...chosen, title: node.title ?? chosen.title, description: node.description ?? chosen.description, default: node.default ?? chosen.default }, path, required && !optional);
      }
      const title = node.title ?? humanize(path);
      return (
        <fieldset key={path}>
          <legend>{title}</legend>
          {optional && (
            <label className="inv-check">
              <input type="checkbox" checked={current != null} onChange={e => onChange(setPath(value, path, e.target.checked ? {} : undefined))} />
              Configure {title.toLowerCase()}
            </label>
          )}
          {(!optional || current != null) && <>
            {variants.length > 1 && (
              <label className="inv-field"><span>{title} method</span>
                <select value={String(method ?? chosen.properties?.method?.const ?? "")} onChange={e => onChange(setPath(value, path, { method: e.target.value }))}>
                  {variants.map((v, i) => <option key={i} value={v.properties?.method?.const ?? i}>{v.title ?? v.properties?.method?.const ?? i}</option>)}
                </select>
              </label>
            )}
            {walk(chosen, path, required)}
          </>}
        </fieldset>
      );
    }
    if (node.properties) {
      return (
        <div key={path} className="config-fields">
          {Object.entries(node.properties).map(([name, child]) => walk(child, path ? `${path}.${name}` : name, !!node.required?.includes(name)))}
        </div>
      );
    }
    if (!path || node.const !== undefined) return null;
    const field = metadata.fields.find(f => f.path === path && f.category === category);
    const label = field?.label || node.title || humanize(path);
    const secret = !!field?.secret;
    const inputId = `${id}-${path}`;
    const displayed = current ?? (secret ? "" : node.default) ?? "";
    const update = (v: unknown) => onChange(setPath(value, path, v));
    const numeric = ["integer", "number"].includes(node.type ?? "");
    let input: React.ReactNode;
    if (node.enum) {
      input = (
        <select id={inputId} value={String(displayed)} onChange={e => update(e.target.value || undefined)}>
          <option value="">Use default</option>
          {node.enum.map(v => <option key={String(v)} value={String(v)}>{v}</option>)}
        </select>
      );
    } else if (node.type === "boolean") {
      input = <input id={inputId} type="checkbox" checked={displayed === true} onChange={e => update(e.target.checked)} />;
    } else if (node.type === "array" || node.type === "object") {
      input = <JsonField id={inputId} value={displayed} onChange={update} />;
    } else if (node.format === "multiline" && path === "location_sites") {
      input = <>
        <textarea id={inputId} value={String(displayed)} onChange={e => update(e.target.value)} />
        <LocationSiteLine onAdd={line => update(String(displayed).trim() ? `${String(displayed).trimEnd()}\n${line}` : line)} />
      </>;
    } else if (node.format === "multiline") {
      input = <textarea id={inputId} value={String(displayed)} onChange={e => update(e.target.value)} />;
    } else {
      input = (
        <input id={inputId} type={secret ? "password" : numeric ? "number" : "text"} autoComplete={secret ? "new-password" : "off"}
          required={required && !editing && node.default === undefined} value={String(displayed)}
          onChange={e => update(e.target.value === "" ? undefined : numeric ? Number(e.target.value) : e.target.value)} />
      );
    }
    return (
      <div key={path} className="config-field">
        <label htmlFor={inputId}>{label}</label>
        {node.description && <p className="sub">{node.description}</p>}
        {markIdentity && (field?.identity_sensitivity === "identity" || field?.identity_sensitivity === "scope") && (
          <p className="sub field-identity">Source identity</p>
        )}
        {input}
      </div>
    );
  }
  return <>{walk(root, "")}</>;
}
function LocationSiteLine({ onAdd }: { onAdd: (line: string) => void }) {
  const [location, setLocation] = useState("");
  const [site, setSite] = useState<{ id: string; code: string } | null>(null);
  return (
    <div className="inv-inline-form">
      <label className="inv-field"><span>Location id or name</span>
        <input value={location} onChange={e => setLocation(e.target.value)} />
      </label>
      <SitePicker label="Site" value={site?.id ?? ""} onChange={(id, picked) => setSite(picked ? { id, code: picked.code } : null)} />
      <button type="button" className="secondary" disabled={!location.trim() || !site}
        onClick={() => { onAdd(`${location.trim()}, ${site!.code}`); setLocation(""); setSite(null); }}>
        Add line
      </button>
    </div>
  );
}
function JsonField({ id, value, onChange }: { id: string; value: unknown; onChange: (value: unknown) => void }) {
  const [text, setText] = useState(() => value === "" ? "" : JSON.stringify(value, null, 2));
  return <textarea id={id} value={text} onChange={e => { setText(e.target.value); try { const next = e.target.value ? JSON.parse(e.target.value) : undefined; onChange(next); e.target.setCustomValidity(""); } catch { e.target.setCustomValidity("Not valid JSON"); } }} />;
}
/** Seed selected discriminator literals and scalar defaults, without making optional blocks active. */
export function materialize(schema: SourceTypeSchema, metadata: CollectorFieldMetadata, category: FieldCategory, draft: Value): Value {
  const root = schema as Node;
  function visit(raw: Node, path: string, input: unknown): unknown {
    if (path && !allowed(path, metadata, category)) return undefined;
    const node = resolve(raw, root);
    const variants = (node.oneOf ?? node.anyOf)?.filter(v => v.type !== "null").map(v => resolve(v, root));
    if (variants?.length) {
      if (input === undefined && node.anyOf?.some(v => v.type === "null")) return undefined;
      const method = (input as Value | undefined)?.method;
      return visit(variants.find(v => v.properties?.method?.const === method) ?? variants[0], path, input);
    }
    if (node.properties) {
      const obj: Value = {};
      for (const [name, child] of Object.entries(node.properties)) {
        const nextPath = path ? `${path}.${name}` : name;
        const v = name === "method" && child.const !== undefined ? child.const : visit(child, nextPath, (input as Value | undefined)?.[name]);
        if (v !== undefined) obj[name] = v;
      }
      return obj;
    }
    return input ?? node.const ?? node.default;
  }
  return visit(root, "", draft) as Value;
}
