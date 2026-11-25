/**
 * The form renders the JSON schema of a source type from GET /api/source-types.
 */

import { useState, type FormEvent, type ReactNode } from "react";
import type { Source, SourceTypeField, SourceTypeSchema } from "../api/types";

const SUPPORTED_TYPES: ReadonlySet<string> = new Set(["string", "integer", "number", "boolean"]);
const HIDDEN_FIELDS: ReadonlySet<string> = new Set(["source_name"]);

// Top-level fields rendered in the "Collection" fieldset.
const COLLECTION_FIELDS: ReadonlySet<string> = new Set([
  "interval_s",
  "transport",
  "timeout",
  "connect_timeout",
  "read_timeout",
  "capture_bgp",
]);

type Schema = SourceTypeSchema & { $defs?: Record<string, SourceTypeSchema> };
type FieldValue = string | boolean;
type FieldEntry = [string, SourceTypeField];

function isSecretField(field: SourceTypeField): boolean {
  return field.writeOnly === true || field.format === "password";
}

function isMultilineField(field: SourceTypeField): boolean {
  return field.type === "string" && field.format === "multiline";
}

function isSourceField(field: SourceTypeField): boolean {
  return field.type === "string" && field.format === "source";
}

function sourceOptions(field: SourceTypeField, sources: Source[]): string[] {
  return sources
    .filter((source) => !field.sourceType || source.type === field.sourceType)
    .map((source) => source.name);
}

function initialValue(field: SourceTypeField, current: unknown): FieldValue {
  if (isSecretField(field)) return "";
  const raw = current ?? field.default;
  if (field.type === "boolean") return raw === true;
  return raw === undefined || raw === null ? "" : String(raw);
}

// $defs holds every nested model of pydantic v2's model_json_schema().

/** Resolves a node to its definition. Pydantic v2 emits a `$ref` bare, with
 *  sibling keys (title/default), or wrapped in a single-element `allOf`. */
function deref(node: any, root: Schema): any {
  if (node && Array.isArray(node.allOf) && node.allOf.length === 1) {
    return deref({ ...node.allOf[0], ...node, allOf: undefined }, root);
  }
  if (node && typeof node.$ref === "string") {
    const target = root.$defs?.[node.$ref.replace("#/$defs/", "")] ?? {};
    const { $ref: _ref, ...siblings } = node;
    return { ...target, ...siblings };
  }
  return node;
}

function isObjectNode(node: any): boolean {
  return node?.type === "object" && node.properties;
}

function unionVariants(node: any): any[] | null {
  const members = node?.oneOf ?? node?.anyOf;
  if (!Array.isArray(members)) return null;
  const real = members.filter((m: any) => m?.type !== "null");
  return real.length > 1 ? real : null;
}

/** The `method` literal identifying a union variant. Pydantic emits the
 *  Literal default as `default` (and `const` for a Literal type). */
function variantMethod(variant: any): string {
  const m = variant.properties?.method ?? {};
  return m.const ?? m.default ?? variant.title ?? "";
}

function methodLiteralOf(node: any): string | undefined {
  return node.properties?.method ? variantMethod(node) : undefined;
}

type Resolved =
  | { kind: "unsupported" }
  | { kind: "scalar"; node: any }
  | { kind: "object"; node: any }
  | { kind: "optional-object"; node: any }
  | { kind: "union"; variants: any[] };

/** Classifies one property's raw schema node. */
function resolve(raw: any, root: Schema): Resolved {
  const variants = unionVariants(raw);
  if (variants) {
    return { kind: "union", variants: variants.map((v) => deref(v, root)) };
  }
  // An `anyOf`/`oneOf` with one non-null member is an optional nested object.
  const members = raw?.anyOf ?? raw?.oneOf;
  if (Array.isArray(members)) {
    const real = members.filter((m: any) => m?.type !== "null");
    if (real.length === 1) {
      const resolved = deref(real[0], root);
      if (isObjectNode(resolved)) return { kind: "optional-object", node: resolved };
    }
  }
  const resolved = deref(raw, root);
  if (isObjectNode(resolved)) return { kind: "object", node: resolved };
  if (SUPPORTED_TYPES.has(resolved?.type)) return { kind: "scalar", node: resolved };
  return { kind: "unsupported" };
}

function skip(name: string): boolean {
  return HIDDEN_FIELDS.has(name) || name === "method";
}

function getAtPath(obj: unknown, path: string): unknown {
  let node: any = obj;
  for (const part of path.split(".")) {
    if (node == null) return undefined;
    node = node[part];
  }
  return node;
}

function setPath(target: Record<string, unknown>, path: string, value: unknown) {
  const parts = path.split(".");
  let node = target;
  for (const part of parts.slice(0, -1)) {
    node[part] = (node[part] as Record<string, unknown>) ?? {};
    node = node[part] as Record<string, unknown>;
  }
  node[parts[parts.length - 1]] = value;
}

function initialMethod(path: string, variants: any[], config: Record<string, unknown> | undefined): string {
  const stored = getAtPath(config, `${path}.method`);
  return typeof stored === "string" ? stored : variantMethod(variants[0]);
}

/** Collects every leaf scalar field as a `(dotted path, field)` pair. */
function collectLeaves(
  prefix: string,
  node: any,
  root: Schema,
  methodByPath: Record<string, string>,
): FieldEntry[] {
  const out: FieldEntry[] = [];
  for (const [name, raw] of Object.entries(node.properties ?? {}) as [string, any][]) {
    if (skip(name)) continue;
    const path = prefix ? `${prefix}.${name}` : name;
    const resolved = resolve(raw, root);
    if (resolved.kind === "scalar") {
      out.push([path, resolved.node]);
    } else if (resolved.kind === "object" || resolved.kind === "optional-object") {
      out.push(...collectLeaves(path, resolved.node, root, methodByPath));
    } else if (resolved.kind === "union") {
      const selected = methodByPath[path] ?? variantMethod(resolved.variants[0]);
      const variant = resolved.variants.find((v) => variantMethod(v) === selected) ?? resolved.variants[0];
      out.push(...collectLeaves(path, variant, root, methodByPath));
    }
  }
  return out;
}

function initMethods(
  prefix: string,
  node: any,
  root: Schema,
  config: Record<string, unknown> | undefined,
  acc: Record<string, string>,
): Record<string, string> {
  for (const [name, raw] of Object.entries(node.properties ?? {}) as [string, any][]) {
    if (skip(name)) continue;
    const path = prefix ? `${prefix}.${name}` : name;
    const resolved = resolve(raw, root);
    if (resolved.kind === "object" || resolved.kind === "optional-object") {
      initMethods(path, resolved.node, root, config, acc);
    } else if (resolved.kind === "union") {
      const selected = initialMethod(path, resolved.variants, config);
      acc[path] = selected;
      const variant = resolved.variants.find((v) => variantMethod(v) === selected) ?? resolved.variants[0];
      initMethods(path, variant, root, config, acc);
    }
  }
  return acc;
}

function isActiveOptional(
  path: string,
  touched: ReadonlySet<string>,
  initialConfig: Record<string, unknown> | undefined,
): boolean {
  if (getAtPath(initialConfig, path) != null) return true;
  for (const t of touched) {
    if (t === path || t.startsWith(`${path}.`)) return true;
  }
  return false;
}

function buildConfig(
  root: Schema,
  values: Record<string, FieldValue>,
  methodByPath: Record<string, string>,
  touched: ReadonlySet<string>,
  initialConfig: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const target: Record<string, unknown> = {};

  function walk(prefix: string, node: any) {
    const required = new Set<string>(node.required ?? []);
    for (const [name, raw] of Object.entries(node.properties ?? {}) as [string, any][]) {
      if (skip(name)) continue;
      const path = prefix ? `${prefix}.${name}` : name;
      const resolved = resolve(raw, root);
      if (resolved.kind === "scalar") {
        const field = resolved.node;
        const value = values[path];
        if (isSecretField(field)) {
          if (typeof value === "string" && value !== "") setPath(target, path, value);
          continue;
        }
        if (field.type === "integer" || field.type === "number") {
          // Number("") is 0.
          const text = typeof value === "string" ? value.trim() : "";
          if (text === "" && !required.has(name)) continue;
          setPath(target, path, Number(text));
        } else if (field.type === "boolean") {
          setPath(target, path, value === true);
        } else {
          setPath(target, path, value);
        }
      } else if (resolved.kind === "object") {
        const literal = methodLiteralOf(resolved.node);
        if (literal !== undefined) setPath(target, `${path}.method`, literal);
        walk(path, resolved.node);
      } else if (resolved.kind === "optional-object") {
        if (!isActiveOptional(path, touched, initialConfig)) continue;
        const literal = methodLiteralOf(resolved.node);
        if (literal !== undefined) setPath(target, `${path}.method`, literal);
        walk(path, resolved.node);
      } else if (resolved.kind === "union") {
        const selected = methodByPath[path] ?? variantMethod(resolved.variants[0]);
        const variant = resolved.variants.find((v) => variantMethod(v) === selected) ?? resolved.variants[0];
        setPath(target, `${path}.method`, selected);
        walk(path, variant);
      }
    }
  }

  walk("", root);
  return target;
}

function ScalarField({
  path,
  field,
  required,
  mode,
  value,
  onChange,
  options,
}: {
  path: string;
  field: SourceTypeField;
  required: boolean;
  mode: "create" | "edit";
  value: FieldValue;
  onChange: (value: FieldValue) => void;
  /** The names a source-picking field may take (`isSourceField`); undefined
   *  for every other field. */
  options?: string[];
}) {
  const secret = isSecretField(field);
  const label = field.title ?? path.split(".").pop() ?? path;
  const inputId = `sf-${path}`;
  // A stored name that matches no source stays selectable.
  const choices =
    options !== undefined && typeof value === "string" && value !== "" && !options.includes(value)
      ? [value, ...options]
      : options;
  return (
    <div className="param sf-field">
      <label htmlFor={inputId}>
        {label}
        {required && (
          <span className="sf-required" aria-hidden="true">
            {" "}
            *
          </span>
        )}
      </label>
      {field.description && <p className="sf-hint">{field.description}</p>}
      {field.type === "boolean" ? (
        <input
          id={inputId}
          type="checkbox"
          checked={value === true}
          onChange={(e) => onChange(e.target.checked)}
        />
      ) : choices !== undefined ? (
        <select
          id={inputId}
          required={required}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">{required ? "Choose a source" : "none"}</option>
          {choices.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      ) : Array.isArray(field.enum) && field.enum.length > 0 && !secret ? (
        <select id={inputId} value={value as string} onChange={(e) => onChange(e.target.value)}>
          {field.enum.map((option) => (
            <option key={String(option)} value={String(option)}>
              {String(option)}
            </option>
          ))}
        </select>
      ) : isMultilineField(field) ? (
        <textarea
          id={inputId}
          required={required}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          id={inputId}
          type={secret ? "password" : field.type === "integer" || field.type === "number" ? "number" : "text"}
          required={required}
          placeholder={secret && mode === "edit" ? "stored value" : undefined}
          autoComplete={secret ? "new-password" : "off"}
          value={value as string}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </div>
  );
}

function groupLabel(name: string): string {
  const words = name.replace(/_/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function renderNode(
  prefix: string,
  node: any,
  root: Schema,
  mode: "create" | "edit",
  values: Record<string, FieldValue>,
  set: (path: string, value: FieldValue) => void,
  methodByPath: Record<string, string>,
  setMethod: (path: string, method: string) => void,
  touched: ReadonlySet<string>,
  initialConfig: Record<string, unknown> | undefined,
  // Every configured source, for a field that picks one by name.
  sources: Source[],
  suppressRequired = false,
): ReactNode[] {
  const required = new Set<string>(node.required ?? []);
  const elements: ReactNode[] = [];
  for (const [name, raw] of Object.entries(node.properties ?? {}) as [string, any][]) {
    if (skip(name)) continue;
    const path = prefix ? `${prefix}.${name}` : name;
    const resolved = resolve(raw, root);
    if (resolved.kind === "unsupported") continue;
    if (resolved.kind === "scalar") {
      const field = resolved.node as SourceTypeField;
      const secret = isSecretField(field);
      // A blank secret on edit keeps the stored value.
      const isRequired = !suppressRequired && required.has(name) && !(secret && mode === "edit");
      elements.push(
        <ScalarField
          key={path}
          path={path}
          field={field}
          required={isRequired}
          mode={mode}
          value={values[path]}
          onChange={(value) => set(path, value)}
          options={isSourceField(field) ? sourceOptions(field, sources) : undefined}
        />,
      );
    } else if (resolved.kind === "object" || resolved.kind === "optional-object") {
      const optional = resolved.kind === "optional-object";
      const childSuppress =
        suppressRequired || (optional && !isActiveOptional(path, touched, initialConfig));
      const children = renderNode(
        path,
        resolved.node,
        root,
        mode,
        values,
        set,
        methodByPath,
        setMethod,
        touched,
        initialConfig,
        sources,
        childSuppress,
      );
      if (children.length === 0) continue;
      elements.push(
        <fieldset className="sf-group" key={path}>
          <legend>
            {groupLabel(name)}
            {optional && <span className="sf-optional"> optional</span>}
          </legend>
          {children}
        </fieldset>,
      );
    } else if (resolved.kind === "union") {
      const selected = methodByPath[path] ?? variantMethod(resolved.variants[0]);
      const variant =
        resolved.variants.find((v) => variantMethod(v) === selected) ?? resolved.variants[0];
      const label = `${raw.title ?? name} method`;
      const selectId = `sf-${path}-method`;
      elements.push(
        <div className="param sf-field" key={`${path}\0method`}>
          <label htmlFor={selectId}>{label}</label>
          <select id={selectId} value={selected} onChange={(e) => setMethod(path, e.target.value)}>
            {resolved.variants.map((v) => {
              const m = variantMethod(v);
              return (
                <option key={m} value={m}>
                  {v.title ?? m}
                </option>
              );
            })}
          </select>
        </div>,
      );
      elements.push(
        ...renderNode(
          path,
          variant,
          root,
          mode,
          values,
          set,
          methodByPath,
          setMethod,
          touched,
          initialConfig,
          sources,
          suppressRequired,
        ),
      );
    }
  }
  return elements;
}

export function SchemaForm({
  schema,
  config,
  mode,
  submitLabel,
  pending = false,
  error = null,
  onSubmit,
  onSubmitConnection,
  onSubmitCollection,
  sources = [],
}: {
  schema: SourceTypeSchema;
  /** Existing (non-secret) config values, for edit mode. */
  config?: Record<string, unknown>;
  mode: "create" | "edit";
  submitLabel: string;
  pending?: boolean;
  error?: string | null;
  onSubmit: (config: Record<string, unknown>) => void;
  onSubmitConnection?: (config: Record<string, unknown>) => void;
  onSubmitCollection?: (config: Record<string, unknown>) => void;
  /** Every configured source, for a field that picks one by name. */
  sources?: Source[];
}) {
  const root = schema as Schema;
  const [methodByPath, setMethodByPath] = useState<Record<string, string>>(() =>
    initMethods("", root, root, config, {}),
  );
  const [values, setValues] = useState<Record<string, FieldValue>>(() =>
    Object.fromEntries(
      collectLeaves("", root, root, methodByPath).map(([path, field]) => [
        path,
        initialValue(field, getAtPath(config, path)),
      ]),
    ),
  );
  const [touched, setTouched] = useState<ReadonlySet<string>>(() => new Set());

  function set(path: string, value: FieldValue) {
    setValues((prev) => ({ ...prev, [path]: value }));
    setTouched((prev) => new Set(prev).add(path));
  }

  function setMethod(path: string, method: string) {
    const nextMethods = { ...methodByPath, [path]: method };
    setMethodByPath(nextMethods);
    // Seeds the fields of the new variant so no input receives `undefined`.
    setValues((prev) => {
      const merged = { ...prev };
      for (const [p, field] of collectLeaves("", root, root, nextMethods)) {
        if (!(p in merged)) merged[p] = initialValue(field, getAtPath(config, p));
      }
      return merged;
    });
    setTouched((prev) => new Set(prev).add(path));
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    onSubmit(buildConfig(root, values, methodByPath, touched, config));
  }

  function sectionConfig(collection: boolean) {
    const built = buildConfig(root, values, methodByPath, touched, config);
    return Object.fromEntries(
      Object.entries(built).filter(([name]) => COLLECTION_FIELDS.has(name) === collection),
    );
  }

  // Both parts render with prefix "".
  const topProperties = Object.entries((root.properties ?? {}) as Record<string, unknown>);
  const mainNode = {
    ...root,
    properties: Object.fromEntries(topProperties.filter(([name]) => !COLLECTION_FIELDS.has(name))),
  };
  const collectionNode = {
    ...root,
    properties: Object.fromEntries(topProperties.filter(([name]) => COLLECTION_FIELDS.has(name))),
  };
  const collectionFields = renderNode(
    "",
    collectionNode,
    root,
    mode,
    values,
    set,
    methodByPath,
    setMethod,
    touched,
    config,
    sources,
  );

  return (
    <form className="editorcard schemaform" onSubmit={handleSubmit} aria-label={`${schema.title ?? "source"} config`}>
      {renderNode("", mainNode, root, mode, values, set, methodByPath, setMethod, touched, config, sources)}
      {collectionFields.length > 0 && (
        <fieldset className="sf-group">
          <legend>Collection</legend>
          {collectionFields}
        </fieldset>
      )}
      {error && (
        <div className="banner err">
          <div className="sub">{error}</div>
        </div>
      )}
      <div className="bar">
        {mode === "edit" && onSubmitConnection && onSubmitCollection ? (
          <>
            <button className="primary" type="button" disabled={pending} onClick={() => onSubmitConnection(sectionConfig(false))}>
              {pending ? "Saving" : "Save connection"}
            </button>
            {collectionFields.length > 0 && (
              <button className="primary" type="button" disabled={pending} onClick={() => onSubmitCollection(sectionConfig(true))}>
                {pending ? "Saving" : "Save collection"}
              </button>
            )}
          </>
        ) : (
          <button className="primary" type="submit" disabled={pending}>
            {pending ? "Saving" : submitLabel}
          </button>
        )}
      </div>
    </form>
  );
}
