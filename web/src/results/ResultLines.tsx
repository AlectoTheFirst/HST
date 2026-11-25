import { missingText, testedText, type ResultValue } from "./text";

/** The 3 lines of a result: the subject and the answer, what was tested, and
 *  the data, with what is missing when the answer is not decided. */
export function ResultLines({ subject, result, run, className }: {
  subject: string;
  result: ResultValue;
  run?: string | number | null;
  className?: string;
}) {
  const tested = testedText(result);
  const missing = missingText(result);
  const data = missing ?? (run ? `All data on the path is in run ${run}.` : "All data on the path was collected.");
  return (
    <div className={className}>
      <p>{subject}: {result.word}.</p>
      {tested && <p>{tested}</p>}
      <p>{data}</p>
    </div>
  );
}
