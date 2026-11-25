/**
 * The probe renders the page context of the next question as JSON.
 */

import { screen } from "@testing-library/react";
import { useAiPageContext } from "../ai/context";

export function PageContextProbe() {
  const context = useAiPageContext();
  return <pre data-testid="page-context">{JSON.stringify(context)}</pre>;
}

/** The context the probe shows; null outside an AiContextProvider. */
export function readPageContext(): any {
  return JSON.parse(screen.getByTestId("page-context").textContent ?? "null");
}
