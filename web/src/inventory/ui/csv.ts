/** The start of a cell that a spreadsheet runs as a formula. */
const FORMULA = /^'*[=+\-@\t\r]/;

/** RFC 4180 CSV. The delimiter is the comma, semicolon or tab that occurs most
 * in the header line. */
export function parseCsv(text: string): string[][] {
  const body = text.replace(/^\uFEFF/, "");
  const header = body.split(/\r?\n/, 1)[0] ?? "";
  const delimiter = [",", ";", "\t"].map(d => [d, header.split(d).length] as const).sort((a, b) => b[1] - a[1])[0][0];
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quoted) {
      if (ch === '"' && body[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field === "") {
      quoted = true;
    } else if (ch === delimiter) {
      row.push(field); field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && body[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.some(cell => cell !== "")) rows.push(row);
      row = [];
    } else {
      field += ch;
    }
  }
  row.push(field);
  if (row.some(cell => cell !== "")) rows.push(row);
  return rows.map(r => r.map(cell => cell.trim()).map(cell => (cell.startsWith("'") && FORMULA.test(cell) ? cell.slice(1) : cell)));
}

export function toCsv(rows: ReadonlyArray<ReadonlyArray<string | number | null | undefined>>): string {
  const cell = (value: string | number | null | undefined) => {
    const text = typeof value === "string" && FORMULA.test(value) ? `'${value}` : value == null ? "" : String(value);
    return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  };
  return rows.map(r => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

export function downloadText(filename: string, text: string, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/** Header cells compared without case, spaces or punctuation. */
export function headerIndex(header: string[], names: string[]): number {
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const wanted = names.map(norm);
  return header.findIndex(cell => wanted.includes(norm(cell)));
}
