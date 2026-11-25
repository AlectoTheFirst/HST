import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Transcript } from "./Transcript";

const base = { runningSteps: [], isPending: false, isLoading: false, error: null };

describe("Transcript", () => {
  it("shows the turns, the extras of an answer and the notes", () => {
    render(
      <Transcript
        chat={{
          ...base,
          isPending: true,
          error: "the request failed",
          turns: [
            { role: "user", content: "which path?" },
            { role: "assistant", content: "the **first** one", declined: true },
          ],
        }}
        extras={() => <span>extra line</span>}
      />,
    );
    expect(screen.getByText("which path?")).toBeTruthy();
    expect(screen.getByText("first").tagName).toBe("STRONG");
    expect(document.querySelector(".chat-md.agentpanel-declined")).not.toBeNull();
    expect(screen.getByText("extra line")).toBeTruthy();
    expect(screen.getByText("Working")).toBeTruthy();
    expect(screen.getByText("the request failed")).toBeTruthy();
  });
});
