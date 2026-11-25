# CLAUDE.md

Instructions for Claude Code in this repository.

## Current information only

Docs, code comments, docstrings, commit-tracked notes and test descriptions state only the current design and the current state. They do not tell the history of the project: no earlier decision, earlier design, earlier value or rejected option. If a design or a value changes, overwrite the old text. Git history keeps the old states. A text about the running system can use the past tense and state changes: "A collection target no longer exists or is disabled." is correct.

## No AI slop

AI slop is forbidden. It applies to each text that Claude writes for this project:

- the product text of the web UI: a label, a button, a column head, a section head, a placeholder, a hint, a note, a `title`, an `aria-label`, an option of a select, an empty state
- the API text: a problem title and detail, a description of an operation, an argument or a field, an OpenAPI or MCP text, a CLI help text and error
- the reason text and the evidence text of a trace, an impact analysis or an audit
- the README, the docs, the code comments, the docstrings and the test names
- the commit messages, the pull request texts, the review comments and the answers to the owner

AI slop is a style, not a set of words. It is text that a generator adds and a person does not need. A word is never forbidden by itself. A text is slop when its form matches a style in the table below. Do not change a correct, plain text only because it contains a word that slop text also uses.

### Forbidden styles

| Style | Test | Slop | Plain |
|---|---|---|---|
| Explanation nobody asked for | The text gives a reason, a purpose or a justification that the reader does not need to act. | "COALESCE because NULLs are distinct in a unique index, and ..." | "COALESCE maps NULL to 0 for the unique index." or no comment |
| History and comparison | The text compares the current state with an earlier state of the project or with a rejected option. | "The cap is now per user rather than per process." | "The cap is per user." |
| Contrast pairs | The text states what a thing is not, next to what it is. | "says the file is missing, not that the table was empty" | "says that the file is missing" |
| Hedging | The text weakens a fact that the code or the data settles. | "This should usually return the newest run." | "This returns the newest run." |
| Vague amounts | The text gives a size or a count without the number, when the number is known. | "several devices" | "3 devices" |
| Selling | The text praises the product or the code. | "a robust, seamless trace engine" | "the trace engine" |
| Narration | The text describes what the reader sees, what the code obviously does, or what the text is about to say. | "Here we loop over the devices." | no comment |
| Talk to the reader | The text speaks to the reader or to the owner as a person, or uses chat phrases. | "Note that you can ...", "Great question" | the fact alone |
| Summary and padding | The text repeats what the text, the page or the code already says, or opens with an introduction. | "In short, the loader writes the run." | no text |
| Colon chains | One sentence joins 2 or more clauses with colons or semicolons. | "The load landed; what it landed can still be less than the whole device." | "The load can write less than the whole device." |
| Explanation after a colon | A short claim is followed by a colon and its explanation. | "No QOS body means the profile read was refused: the ..." | "The profile read was refused if the QOS body is missing." |
| Verbs as metaphors | Data or code is said to speak, carry or name. | "the row carries the filter", "the leg says so" | "the row holds the filter", "the leg has a note" |
| Compressed fragments | The sentence has no subject, no verb or no articles, so the reader must decode it. | "Not blocked, and not a clean pass: the engine could not decide." | "The engine could not decide the gate." |
| Appended facts | A second fact is joined to the needed fact with "and", "so", "which" or a comma, and the reader does not need it. | "The driver is thread-safe and lives as long as the process." | "The driver is thread-safe." |
| Stacked qualifiers | The noun has 2 or more qualifiers that the reader does not need. | "a confirmed, undecided-free permit, which a later reply ..." | "a permit" |
| Riddle wording | The text uses an unusual phrase where a plain phrase exists. | "past the sample the row says how many" | "after the sample, the row holds the count" |
| Self-reference | The text refers to itself or to its own function in place of the name. | "this function's own parameter" | "the parameter `detail`" |
| Rhetorical forms | The text uses a question, a group of 3 for rhythm, or a fragment for effect. | "Fast, safe, and simple." | no text |
| Decoration | The text uses emoji, glyphs such as `·`, `→`, `✓` and `•`, an em dash, an exclamation mark, bold in running text, or a heading or a table for 2 items. | "Trace →" | "Trace flow" |

Write full, plain sentences: a subject, a verb and an object, with articles. One fact per sentence.

### Product text

- A name is the bare name of the thing: "Network functions", "Forwarding table", "Next hops". It has no qualifier, no format, no unit and no second part after a comma or a colon. A unit goes in the `unit` field of a column or a setting.
- A label names a thing or a state in a few words: "not known", "no reply", "no device group". A button names its action: "Add credential", "Delete core-01".
- A label, a hint, a note or a description is not a sentence and has no full stop. A `title` holds one short phrase at most.
- No text explains a section, or why a thing is absent, disabled or not used. A control that does nothing for the record is not shown.
- No text repeats what the page already shows. A count or a summary box that a person does not act on is not shown.
- A value shows as the value itself, in full, not as "varies", "mixed" or a cut text with an ellipsis.
- No key hints, tips, onboarding text or legends that explain the controls.
- Sentence case, present tense.

### Docs and the README

- State the current design and the current facts only. No plan written as a fact.
- No introduction, no overview that restates the headings, no closing summary, no sales section, no next steps that nobody asked for.

### Code comments, docstrings and test names

- A comment states what the code does or holds, in the terms of the code. If the code already shows it, write no comment.
- A comment keeps a fact that the code depends on: a bound, an order, a format or a constraint.

### Commit messages, pull request texts and answers to the owner

- A commit message names the change: "collectors: NX-OS VRF table in the parser test".
- A pull request text lists the changes and the checks.
- An answer to the owner leads with the result, and then gives only the facts that the owner needs. It does not praise, apologize, restate the question or end with an offer that nobody needs. It does not claim a result that no check confirmed.
- Options go to the owner only when the owner must decide.

Before a change is done, read each new or changed text of the change against this section.
