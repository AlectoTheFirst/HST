import type { AnalysisSession, RevisionReference } from "./contracts";

/** The application revisions a session binds, from its connections and its protections.
 *  With `itemId`, only the connection of that run; a simulation run binds every protection. */
export function applicationReferences(session: AnalysisSession, itemId?: string): RevisionReference[] {
  const input = session.input;
  if (input.kind === "connection")
    return input.connections.flatMap((connection) =>
      connection.source.kind === "application_connection" && (itemId == null || connection.id === itemId)
        ? [connection.source.reference.application]
        : [],
    );
  return (input.protected ?? []).flatMap((protection) =>
    protection.kind === "application_connection" ? [protection.reference.application] : [],
  );
}

export type CurrentRevisions = ReadonlyMap<string, { revision: number; name: string }>;

/** One text per application bound to an older revision, such as
 *  "Application revision 1, not revision 2". The application name replaces
 *  "Application" when the references hold more than one application. */
export function staleRevisionTexts(references: RevisionReference[], current: CurrentRevisions | undefined): string[] {
  if (!current) return [];
  const bound = new Map<string, Set<number>>();
  for (const reference of references) {
    const revisions = bound.get(reference.id) ?? new Set<number>();
    revisions.add(reference.revision);
    bound.set(reference.id, revisions);
  }
  return [...bound].flatMap(([id, revisions]) => {
    const latest = current.get(id);
    if (!latest) return [];
    const older = [...revisions].filter((revision) => revision !== latest.revision).sort((a, b) => a - b);
    if (older.length === 0) return [];
    const subject = bound.size > 1 ? latest.name : "Application";
    return [`${subject} revision ${older.join(", ")}, not revision ${latest.revision}`];
  });
}
