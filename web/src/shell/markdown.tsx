/**
 * The renderer turns the HST AI transcript markdown into React elements.
 *
 * With `citations`, the step markers of an answer, `[s3]` or `[s3, s5]`,
 * render as the chips it builds. A claim tag (`claimTag`) before a marker
 * names the statement the marker belongs to, and the text between
 * HIGHLIGHT_OPEN and HIGHLIGHT_CLOSE renders through `highlight`. The text
 * between a statement tag (`statementTag`) and STATEMENT_CLOSE renders through
 * `statement`. Inside code they stay literal text.
 */

import { Fragment, type ReactNode } from "react";

/** How the step markers of an answer render (ai/citations.tsx). */
export interface Citations {
  /** The chip of one step label, such as `s3`; `claim` is the id of the
   *  statement whose tag precedes the marker. */
  chip: (label: string, key: string, claim?: string) => ReactNode;
  /** The element around the text of a highlighted statement. */
  highlight?: (children: ReactNode, key: string) => ReactNode;
  /** The element around the text of statement `claim`. */
  statement?: (children: ReactNode, key: string, claim: string) => ReactNode;
}

/** Private-use characters, which no answer text holds: they open and close
 *  a claim tag, open and close a highlighted statement, and open and close
 *  the text of a statement. */
const CLAIM_OPEN = "\uE001";
const CLAIM_CLOSE = "\uE002";
export const HIGHLIGHT_OPEN = "\uE003";
export const HIGHLIGHT_CLOSE = "\uE004";
const STATEMENT_OPEN = "\uE005";
export const STATEMENT_CLOSE = "\uE006";
/** The private-use characters the renderer reads. */
export const RESERVED = /[\uE000-\uE006]/g;

/** The tag that names statement `id` before one of its markers. */
export function claimTag(id: string): string {
  return CLAIM_OPEN + id + CLAIM_CLOSE;
}

/** The tag that opens the text of statement `id`. */
export function statementTag(id: string): string {
  return STATEMENT_OPEN + id + CLAIM_CLOSE;
}

/** A step marker as src/hst/app/ai/envelope.py reads it, after an optional
 *  claim tag, a statement tag, or a highlight or statement close character. */
const CITATION = new RegExp(
  `(?:${CLAIM_OPEN}([^${CLAIM_CLOSE}]{1,32})${CLAIM_CLOSE})?\\[(s\\d{1,9}(?:[ \\t]*,[ \\t]*s\\d{1,9})*)\\]|${STATEMENT_OPEN}([^${CLAIM_CLOSE}]{1,32})${CLAIM_CLOSE}|[${HIGHLIGHT_OPEN}${HIGHLIGHT_CLOSE}${STATEMENT_CLOSE}]`,
  "g",
);

/** The citations of one render, whether the text read so far is inside a
 *  highlighted statement, and the statement it is inside. */
interface Render {
  citations: Citations;
  marking: boolean;
  marks: number;
  statement?: string;
}

/** Plain text, with its markers as chips when the render has citations. `at`
 *  is the offset of `text` in its block, which keeps the chip keys unique. */
function cite(text: string, at: number, render?: Render): ReactNode[] {
  if (!render) return [text];
  const { citations } = render;
  const out: ReactNode[] = [];
  const plain = (piece: string) => {
    if (!piece) return;
    let node: ReactNode = piece;
    if (render.statement !== undefined && citations.statement) {
      node = citations.statement(node, `statement-${render.marks++}`, render.statement);
    }
    if (render.marking && citations.highlight) node = citations.highlight(node, `mark-${render.marks++}`);
    out.push(node);
  };
  let last = 0;
  for (const m of text.matchAll(CITATION)) {
    plain(text.slice(last, m.index));
    const key = `cite-${at + m.index}`;
    if (m[2] !== undefined) {
      m[2].split(",").forEach((label, i) => out.push(citations.chip(label.trim(), `${key}-${i}`, m[1])));
    } else if (m[3] !== undefined) render.statement = m[3];
    else if (m[0] === STATEMENT_CLOSE) render.statement = undefined;
    else render.marking = m[0] === HIGHLIGHT_OPEN;
    last = m.index + m[0].length;
  }
  plain(text.slice(last));
  return out;
}

/** Inline spans match in the order `code`, **bold**, *italic*. */
function renderInline(text: string, citations?: Render): ReactNode {
  const out: ReactNode[] = [];
  // one scan, earliest match wins; unterminated markers stay literal text
  const pattern = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*\s][^*]*)\*/g;
  let last = 0;
  for (const m of text.matchAll(pattern)) {
    if (m.index > last) out.push(...cite(text.slice(last, m.index), last, citations));
    if (m[1] !== undefined) out.push(<code key={m.index}>{m[1]}</code>);
    else if (m[2] !== undefined) out.push(<strong key={m.index}>{renderInline(m[2], citations)}</strong>);
    else out.push(<em key={m.index}>{renderInline(m[3], citations)}</em>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(...cite(text.slice(last), last, citations));
  return out.length === 1 ? out[0] : out;
}

function isTableRow(line: string): boolean {
  const t = line.trim();
  return t.startsWith("|") && t.endsWith("|") && t.length > 1;
}

function isDividerRow(line: string): boolean {
  // | --- | :---: |, the separator between header and body
  return isTableRow(line) && /^[|\s:-]+$/.test(line.trim());
}

function splitRow(line: string): string[] {
  const t = line.trim();
  return t.slice(1, t.endsWith("|") ? -1 : undefined).split("|");
}

function table(lines: string[], key: number, citations?: Render): ReactNode {
  const rows = lines.filter((l) => !isDividerRow(l)).map(splitRow);
  const hasHeader = lines.length > 1 && isDividerRow(lines[1]);
  const head = hasHeader ? rows[0] : null;
  const body = hasHeader ? rows.slice(1) : rows;
  return (
    <div className="md-tablewrap" key={key}>
      <table>
        {head && (
          <thead>
            <tr>
              {head.map((c, i) => (
                <th key={i}>{renderInline(c.trim(), citations)}</th>
              ))}
            </tr>
          </thead>
        )}
        <tbody>
          {body.map((cells, r) => (
            <tr key={r}>
              {cells.map((c, i) => (
                <td key={i}>{renderInline(c.trim(), citations)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const UL = /^\s*[-*]\s+(.*)$/;
const OL = /^\s*(\d+)[.)]\s+(.*)$/;
const HEADING = /^(#{1,4})\s+(.*)$/;

/** Block-level pass. Returns a fragment of paragraphs, lists, tables, code. */
export function renderMarkdown(text: string, chips?: Citations): ReactNode {
  const citations: Render | undefined = chips && { citations: chips, marking: false, marks: 0 };
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i++;
      continue;
    }

    if (line.trimStart().startsWith("```")) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) code.push(lines[i++]);
      i++; // closing fence (or end of input on an unterminated block)
      blocks.push(
        <pre className="md-code" key={key++}>
          {code.join("\n")}
        </pre>,
      );
      continue;
    }

    if (isTableRow(line)) {
      const rows: string[] = [];
      while (i < lines.length && isTableRow(lines[i])) rows.push(lines[i++]);
      blocks.push(table(rows, key++, citations));
      continue;
    }

    const ul = UL.exec(line);
    const ol = OL.exec(line);
    if (ul || ol) {
      const ordered = !!ol;
      const items: string[] = [];
      while (i < lines.length) {
        const m = ordered ? OL.exec(lines[i]) : UL.exec(lines[i]);
        if (!m) break;
        items.push(ordered ? m[2] : m[1]);
        i++;
      }
      const children = items.map((item, j) => <li key={j}>{renderInline(item, citations)}</li>);
      blocks.push(ordered ? <ol key={key++}>{children}</ol> : <ul key={key++}>{children}</ul>);
      continue;
    }

    const h = HEADING.exec(line);
    if (h) {
      blocks.push(
        <p className="md-heading" key={key++}>
          {renderInline(h[2], citations)}
        </p>,
      );
      i++;
      continue;
    }

    // paragraph: consecutive plain lines joined; a single newline is a wrap
    const para: string[] = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].trimStart().startsWith("```") &&
      !isTableRow(lines[i]) &&
      !UL.test(lines[i]) &&
      !OL.test(lines[i]) &&
      !HEADING.test(lines[i])
    ) {
      para.push(lines[i++]);
    }
    blocks.push(<p key={key++}>{renderInline(para.join("\n"), citations)}</p>);
  }

  return <Fragment>{blocks}</Fragment>;
}
