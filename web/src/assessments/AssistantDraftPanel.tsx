import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { objectDescription } from "./guided";
import type { DiscoveryObject } from "./guided";
import type { AnalysisKind, AssessmentDraft, Definition } from "./types";
import { emptyRequirement } from "./types";

type Candidate = DiscoveryObject;
interface Selection {
  uid: string;
  kind: string;
  device_uid?: string;
  origin?: "graph" | "saved";
  requirement_revision?: number;
}
interface Suggestion {
  status: string;
  detail?: string;
  title: string;
  kind: AnalysisKind;
  snapshot: string;
  definition?: Definition;
  analysis?: Record<string, unknown>;
  plan: unknown;
  candidates: Candidate[];
  selections: Candidate[];
  questions: string[];
  assumptions: string[];
  ready: boolean;
  truncated: boolean;
  clues?: Record<string, string>[];
}

/** AI only fills the same review form. Selection is explicit, even for one match. */
interface Props {
  snapshot: string;
  onDraft: (draft: AssessmentDraft) => void;
  onManual?: (clues: Record<string, string>) => void;
  initialQuestion?: string;
}
export function AssistantDraftPanel(props: Props) {
  return <AssistantDraft key={props.snapshot} {...props} />;
}
function AssistantDraft({ snapshot, onDraft, onManual, initialQuestion = "" }: Props) {
  const generation = useRef(0);
  const [question, setQuestion] = useState(initialQuestion);
  const [clarification, setClarification] = useState("");
  const [selection, setSelection] = useState<Selection[]>([]);
  const [result, setResult] = useState<Suggestion | null>(null);
  const [job, setJob] = useState<{ id: string; snapshot: string; generation: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const visible = result?.snapshot === snapshot ? result : null;

  useEffect(() => {
    generation.current += 1;
    return () => {
      generation.current += 1;
    };
  }, [snapshot]);

  useEffect(() => {
    if (!job || job.snapshot !== snapshot) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await api<Suggestion>(
          `/assessment-assistant/drafts/${encodeURIComponent(job!.id)}`,
        );
        if (!active || generation.current !== job!.generation) return;
        if (next.status === "running") {
          timer = setTimeout(poll, 1000);
          return;
        }
        setBusy(false);
        setJob(null);
        if (next.status === "error") setError(next.detail ?? "AI assistance not available");
        else setResult(next);
      } catch (err) {
        if (active && generation.current === job!.generation) {
          setError(err instanceof Error ? err.message : "Could not read the draft");
          setBusy(false);
          setJob(null);
        }
      }
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [job, snapshot]);

  async function prepare(refine = false, clarifiedQuestion = question) {
    const attempt = ++generation.current;
    setBusy(true);
    setError("");
    try {
      const next = await api<{ job_id: string }>("/assessment-assistant/drafts", {
        method: "POST",
        body: {
          snapshot,
          question: clarifiedQuestion,
          selections: refine ? selection : [],
          ...(refine && visible ? { plan: visible.plan } : {}),
        },
      });
      if (generation.current !== attempt) return;
      if (!refine) {
        setSelection([]);
        setResult(null);
      }
      setJob({ id: next.job_id, snapshot, generation: attempt });
    } catch (err) {
      if (generation.current !== attempt) return;
      setError(err instanceof Error ? err.message : "AI assistance not available");
      setBusy(false);
    }
  }
  function choose(item: Candidate, checked: boolean) {
    setResult((old) => (old ? { ...old, ready: false } : old));
    setSelection((old) =>
      checked
        ? [
            ...old.filter(
              (v) =>
                !(
                  v.uid === item.uid &&
                  v.kind === item.kind &&
                  (v.origin ?? "graph") === (item.origin ?? "graph")
                ) && !(item.kind === "service" && v.kind === "service"),
            ),
            {
              uid: item.uid,
              kind: item.kind,
              ...(item.origin === "saved"
                ? { origin: "saved" as const, requirement_revision: item.requirement_revision }
                : {}),
            },
          ]
        : old.filter(
            (v) =>
              !(
                v.uid === item.uid &&
                v.kind === item.kind &&
                (v.origin ?? "graph") === (item.origin ?? "graph")
              ),
          ),
    );
  }
  function answerFollowup() {
    const next = `${question}\nAdditional information: ${clarification.trim()}`;
    if (next.length > 4000) {
      setError("Question and follow-up over 4000 characters");
      return;
    }
    setQuestion(next);
    setClarification("");
    void prepare(false, next);
  }
  function continueManually() {
    const clues = visible?.clues?.find((entry) => entry.kind === "service") ?? {};
    if (onManual) {
      onManual(clues);
      return;
    }
    onDraft({
      title: visible?.title ?? "Troubleshoot a service",
      kind: visible?.kind === "verify" ? "evaluate" : (visible?.kind ?? "troubleshoot"),
      definition: {
        request: emptyRequirement(),
        snapshot,
        intents: [],
        mode: "possible",
        freshness_s: 86400,
      },
      analysis: { service_clues: clues },
    });
  }
  return (
    <section className="assessment-assistant" aria-label="AI assessment assistant">
      <h3>Question</h3>
      <label className="assessment-field">
        <span>Question for AI</span>
        <textarea
          rows={3}
          maxLength={4000}
          value={question}
          placeholder="Checkout page fails from the Berlin office"
          onChange={(e) => {
            generation.current += 1;
            setQuestion(e.target.value);
            setClarification("");
            setResult(null);
            setJob(null);
            setBusy(false);
            setError("");
          }}
        />
      </label>
      {!snapshot && <p>No snapshot selected</p>}
      <button
        type="button"
        disabled={!snapshot || !question.trim() || (busy && (!job || job.snapshot === snapshot))}
        onClick={() => void prepare()}
      >
        Prepare with AI
      </button>
      {busy && (!job || job.snapshot === snapshot) && <p role="status">Preparing a draft</p>}
      {error && <p role="alert">{error}</p>}
      {(error || visible) && (
        <button type="button" disabled={busy || !snapshot} onClick={continueManually}>
          Continue with known traffic
        </button>
      )}
      {visible && (
        <>
          <h4>{visible.title}</h4>
          <p>Suggested workflow: {visible.kind}</p>
          {!!visible.clues?.length && (
            <details>
              <summary>Clues used to find matches</summary>
              <ul>
                {visible.clues.map((entry, index) => (
                  <li key={index}>
                    {Object.entries(entry)
                      .filter(([key, value]) => key !== "kind" && value)
                      .map(([key, value]) => `${key}: ${value}`)
                      .join(", ") || "Browse recorded services"}
                  </li>
                ))}
              </ul>
            </details>
          )}
          <fieldset>
            <legend>Recorded objects</legend>
            {!visible.candidates.length && <p>No recorded match</p>}
            {visible.candidates.map((item) => {
              const selected = selection.find(
                (v) =>
                  v.uid === item.uid &&
                  v.kind === item.kind &&
                  (v.origin ?? "graph") === (item.origin ?? "graph"),
              );
              return (
                <div key={`${item.origin ?? "graph"}:${item.kind}:${item.uid}`}>
                  <label className="assessment-check">
                    <input
                      type="checkbox"
                      checked={!!selected}
                      disabled={busy || !item.selectable}
                      onChange={(e) => choose(item, e.target.checked)}
                    />
                    <span>
                      {item.name}{" "}
                      <small>
                        {[
                          item.origin === "saved"
                            ? `Saved service revision ${item.requirement_revision}`
                            : item.kind,
                          objectDescription(item),
                        ]
                          .filter(Boolean)
                          .join(", ")}
                      </small>
                    </span>
                  </label>
                  {item.definition && (
                    <>
                      <p className="assessment-note">
                        Clients: {item.definition.sources.join(", ")}
                      </p>
                      <p className="assessment-note">Destination: {item.definition.destination}</p>
                      {item.definition.members.map((member) => (
                        <p className="assessment-note" key={member.name}>
                          {member.addresses.join(", ")} /{" "}
                          {member.proto ?? item.definition!.proto ?? "protocol unspecified"} / port{" "}
                          {member.port ?? item.definition!.port ?? "unspecified"}
                        </p>
                      ))}
                    </>
                  )}
                  {Array.isArray(item.match_reasons) && (
                    <ul>
                      {item.match_reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  )}
                  {!item.selectable && (
                    <p className="assessment-note">
                      {item.disabled_reason ?? "Recorded definition incomplete"}
                    </p>
                  )}
                  {selected && item.kind === "rulebase" && (
                    <label className="assessment-field">
                      <span>Device for {item.name}</span>
                      <select
                        disabled={busy}
                        value={selected.device_uid ?? ""}
                        onChange={(e) => {
                          setResult({ ...visible, ready: false });
                          setSelection(
                            selection.map((v) =>
                              v.uid === item.uid ? { ...v, device_uid: e.target.value } : v,
                            ),
                          );
                        }}
                      >
                        <option value="">Choose the owning device</option>
                        {item.devices?.map((d) => (
                          <option value={d.uid} key={d.uid}>
                            {d.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                </div>
              );
            })}
          </fieldset>
          {visible.truncated && <p>Match list incomplete</p>}
          <button
            type="button"
            disabled={busy || !selection.length}
            onClick={() => void prepare(true)}
          >
            Use selected objects
          </button>
          {!!visible.questions.length && (
            <div>
              <h4>{visible.ready ? "Complete in review" : "Questions"}</h4>
              <ul>
                {visible.questions.map((q) => (
                  <li key={q}>{q}</li>
                ))}
              </ul>
            </div>
          )}
          <label className="assessment-field">
            <span>Additional clues or answer</span>
            <textarea
              rows={2}
              disabled={busy}
              maxLength={2000}
              value={clarification}
              placeholder="https://shop.example/checkout, Berlin office VPN"
              onChange={(event) => setClarification(event.target.value)}
            />
          </label>
          <button type="button" disabled={busy || !clarification.trim()} onClick={answerFollowup}>
            Find matches with this information
          </button>
          <ul>
            {visible.assumptions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
          {visible.ready && visible.definition && (
            <button
              type="button"
              onClick={() =>
                onDraft({
                  title: visible.title,
                  kind: visible.kind,
                  definition: visible.definition!,
                  analysis: visible.analysis,
                })
              }
            >
              Review draft in guided form
            </button>
          )}
        </>
      )}
    </section>
  );
}
