/**
 * No string of the transcript markdown becomes HTML.
 */

import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import {
  claimTag,
  HIGHLIGHT_CLOSE,
  HIGHLIGHT_OPEN,
  renderMarkdown,
  STATEMENT_CLOSE,
  statementTag,
  type Citations,
} from "./markdown";

function html(md: string): string {
  return render(<div>{renderMarkdown(md)}</div>).container.innerHTML;
}

/** Chips as `<b>` elements, with the claim of a tagged marker as its title,
 *  and highlighted text as `<mark>`. */
const CITATIONS: Citations = {
  chip: (label, key, claim) => (
    <b key={key} className="chip" title={claim}>
      {label}
    </b>
  ),
  highlight: (children, key) => <mark key={key}>{children}</mark>,
};

function cited(md: string): string {
  return render(<div>{renderMarkdown(md, CITATIONS)}</div>).container.innerHTML;
}

describe("transcript markdown", () => {
  it("renders bold, italic and inline code as elements", () => {
    const out = html("a **bold** and *soft* `word`");
    expect(out).toContain("<strong>bold</strong>");
    expect(out).toContain("<em>soft</em>");
    expect(out).toContain("<code>word</code>");
  });

  it("renders a pipe table with a header row", () => {
    const out = html("| # | Hop |\n|---|---|\n| 0 | Endpoint `x` |");
    expect(out).toContain("<th>#</th>");
    expect(out).toContain("<code>x</code>");
    expect(out).not.toContain("|---|");
  });

  it("renders fenced code verbatim, markers and all", () => {
    const out = html("```\nMATCH (n) **not bold** RETURN n\n```");
    expect(out).toContain("MATCH (n) **not bold** RETURN n");
    expect(out).not.toContain("<strong>");
  });

  it("renders lists and headings", () => {
    const out = html("## Path\n- first\n- second\n1. one\n2. two");
    expect(out).toContain("md-heading");
    expect(out).toMatch(/<ul><li>first<\/li><li>second<\/li><\/ul>/);
    expect(out).toMatch(/<ol><li>one<\/li><li>two<\/li><\/ol>/);
  });

  it("never turns markup-looking text into HTML", () => {
    const out = html('paragraph with <script>alert("x")</script> inside');
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;script&gt;");
  });

  it("leaves unterminated markers as the literal text they are", () => {
    const out = html("a **dangling and `open");
    expect(out).toContain("**dangling");
    expect(out).toContain("`open");
  });
});

describe("citation markers", () => {
  it("stay literal text without citations", () => {
    expect(html("fw1 denies the flow [s3].")).toContain("fw1 denies the flow [s3].");
  });

  it("are removed from the text and rendered as chips", () => {
    const out = cited("fw1 denies the flow [s3]. It is **denied [s4]**.");
    expect(out).not.toContain("[s3]");
    expect(out).not.toContain("[s4]");
    expect(out).toContain('fw1 denies the flow <b class="chip">s3</b>.');
    expect(out).toContain('<strong>denied <b class="chip">s4</b></strong>');
  });

  it("render one chip per label of a grouped marker", () => {
    const out = cited("fw1 permits tcp/443 [s1, s3]");
    expect(out).toContain('<b class="chip">s1</b><b class="chip">s3</b>');
  });

  it("render as chips in list items, table cells and headings", () => {
    const out = cited("## Verdict [s1]\n- fw1 denies it [s2]\n\n| Hop | Device |\n|---|---|\n| 1 | fw1 [s3] |");
    expect(out).toContain('<b class="chip">s1</b>');
    expect(out).toContain('<li>fw1 denies it <b class="chip">s2</b></li>');
    expect(out).toContain('<td>fw1 <b class="chip">s3</b></td>');
    expect(out).not.toMatch(/\[s\d\]/);
  });

  it("stay literal inside inline code and code blocks", () => {
    const out = cited("The query `MATCH (n) [s9]` ran.\n```\nRETURN n [s8]\n```");
    expect(out).toContain("<code>MATCH (n) [s9]</code>");
    expect(out).toContain("RETURN n [s8]");
    expect(out).not.toContain("chip");
  });

  it("name the statement whose tag precedes the marker", () => {
    const out = cited(`fw1 denies the flow ${claimTag("c2")}[s1, s2]. sw2 forwards it [s3].`);
    expect(out).toContain('<b class="chip" title="c2">s1</b><b class="chip" title="c2">s2</b>');
    expect(out).toContain('<b class="chip">s3</b>');
    expect(out).not.toMatch(/[\uE000-\uE004]/);
  });

  it("highlight the text between the highlight marks, across inline spans", () => {
    const out = cited(`fw1 denies it [s1]. ${HIGHLIGHT_OPEN}sw2 **forwards** it.${HIGHLIGHT_CLOSE} Done.`);
    expect(out).toContain("<mark>sw2 </mark><strong><mark>forwards</mark></strong><mark> it.</mark> Done.");
    expect(out).not.toMatch(/[\uE000-\uE004]/);
  });

  it("wrap the text of a tagged statement, in a list item and across the cells of a table row", () => {
    const statements: Citations = {
      ...CITATIONS,
      statement: (children, key, claim) => (
        <span key={key} data-claim={claim}>
          {children}
        </span>
      ),
    };
    const md = [
      `- ${statementTag("c1")}fw1 **denies** it [s1].${STATEMENT_CLOSE}`,
      "",
      "| rule | action |",
      "| --- | --- |",
      `|${statementTag("c2")} 10 | drop ${STATEMENT_CLOSE}|`,
    ].join("\n");
    const out = render(<div>{renderMarkdown(md, statements)}</div>).container.innerHTML;
    expect(out).toContain(
      '<li><span data-claim="c1">fw1 </span><strong><span data-claim="c1">denies</span></strong>' +
        '<span data-claim="c1"> it </span><b class="chip">s1</b><span data-claim="c1">.</span></li>',
    );
    // the row stays a table row; the tags sit inside the cells' padding
    expect(out).toContain('<td><span data-claim="c2"> 10</span></td><td><span data-claim="c2">drop </span></td>');
    expect(out).not.toMatch(/[\uE000-\uE006]/);
  });
});
