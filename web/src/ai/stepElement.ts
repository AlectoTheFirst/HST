/**
 * The element of a tool step in the result cards (ai/ResultCards.tsx), which
 * the Details of a citation's evidence (ai/evidence.tsx) moves to.
 */

/** The id of the element that shows one step. */
export function stepElementId(stepId: string): string {
  return `ai-step-${stepId}`;
}

export function nearestStep(from: HTMLElement, stepId: string): HTMLElement | null {
  const selector = `#${CSS.escape(stepElementId(stepId))}`;
  for (let node = from.parentElement; node; node = node.parentElement) {
    const found = node.querySelector<HTMLElement>(selector);
    if (found) return found;
  }
  return null;
}
