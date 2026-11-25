import { describe, expect, it } from "vitest";
import { useRef, useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useDialogFocus } from "./useDialogFocus";
import { rovingKeys, rovingTabIndex } from "./rovingKeys";

describe("useDialogFocus", () => {
  it("moves the focus in, keeps Tab inside, and gives the focus back on close", async () => {
    const user = userEvent.setup();
    function Dialog({ onClose }: { onClose: () => void }) {
      const card = useRef<HTMLDivElement>(null);
      useDialogFocus(card);
      return (
        <div ref={card} tabIndex={-1} role="dialog" aria-label="test dialog">
          <button type="button" onClick={onClose}>
            Close
          </button>
          <button type="button">Other</button>
        </div>
      );
    }
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            open
          </button>
          {open && <Dialog onClose={() => setOpen(false)} />}
        </>
      );
    }
    render(<Host />);
    const opener = screen.getByRole("button", { name: "open" });
    await user.click(opener);
    const dialog = screen.getByRole("dialog");
    expect(document.activeElement).toBe(dialog);
    await user.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
    await user.tab();
    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});

describe("rovingKeys", () => {
  function Group() {
    const [value, setValue] = useState("a");
    return (
      <div role="radiogroup" aria-label="letters">
        {["a", "b", "c"].map((v, i) => (
          <button
            key={v}
            type="button"
            role="radio"
            aria-checked={value === v}
            tabIndex={rovingTabIndex(value === v, i, true)}
            onKeyDown={rovingKeys("radio")}
            onClick={() => setValue(v)}
          >
            {v}
          </button>
        ))}
      </div>
    );
  }

  it("makes the group one Tab stop and chooses with the arrow keys, Home and End", async () => {
    const user = userEvent.setup();
    render(<Group />);
    await user.tab();
    expect(document.activeElement?.textContent).toBe("a");
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "b" }).getAttribute("aria-checked")).toBe("true");
    expect(document.activeElement?.textContent).toBe("b");
    await user.keyboard("{End}");
    expect(screen.getByRole("radio", { name: "c" }).getAttribute("aria-checked")).toBe("true");
    await user.keyboard("{ArrowRight}");
    expect(document.activeElement?.textContent).toBe("a");
    await user.keyboard("{ArrowLeft}");
    expect(document.activeElement?.textContent).toBe("c");
    expect(screen.getAllByRole("radio").map((r) => r.tabIndex)).toEqual([-1, -1, 0]);
  });

  it("gives the first item the Tab stop when nothing is chosen", () => {
    expect([0, 1].map((i) => rovingTabIndex(false, i, false))).toEqual([0, -1]);
  });
});
