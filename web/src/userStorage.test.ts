import { afterEach, describe, expect, it } from "vitest";
import { claimUserStorage, clearUserStorage, PREFERENCE_KEYS, USER_HISTORY_KEYS, USER_KEYS } from "./userStorage";

const STORAGES = [
  ["localStorage", () => window.localStorage],
  ["sessionStorage", () => window.sessionStorage],
] as const;

afterEach(() => {
  window.sessionStorage.clear();
});

describe.each(STORAGES)("clearUserStorage in %s", (_name, storage) => {
  it("removes each key of USER_KEYS", () => {
    for (const key of USER_KEYS) storage().setItem(key, "1");

    clearUserStorage();

    expect(USER_KEYS.filter((key) => storage().getItem(key) !== null)).toEqual([]);
  });

  it("removes a draft key with a username prefix", () => {
    const drafts = ["hst.inventory.draft:viewer1:site:create", "hst.inventory.draft:anonymous:routing:7:name"];
    for (const key of drafts) storage().setItem(key, "1");

    clearUserStorage();

    expect(drafts.filter((key) => storage().getItem(key) !== null)).toEqual([]);
  });

  it("keeps each key of PREFERENCE_KEYS", () => {
    for (const key of PREFERENCE_KEYS) storage().setItem(key, "1");

    clearUserStorage();

    expect(PREFERENCE_KEYS.filter((key) => storage().getItem(key) === null)).toEqual([]);
  });
});

describe("clearUserStorage in the current history entry", () => {
  it("removes each key of USER_HISTORY_KEYS and keeps the other keys and the URL", () => {
    const state: Record<string, unknown> = { idx: 3 };
    for (const key of USER_HISTORY_KEYS) state[key] = "1";
    window.history.replaceState(state, "", "/?analysis=session-2");

    clearUserStorage();

    expect(window.history.state).toEqual({ idx: 3 });
    expect(window.location.search).toBe("?analysis=session-2");
    window.history.replaceState(null, "", "/");
  });
});

describe("claimUserStorage", () => {
  it("removes the stored data of another user and records the owner", () => {
    window.localStorage.setItem("hst.user", "ada");
    window.localStorage.setItem("hst-workspace", "{}");
    window.localStorage.setItem("hst-theme", "dark");
    claimUserStorage("vera");
    expect(window.localStorage.getItem("hst-workspace")).toBeNull();
    expect(window.localStorage.getItem("hst-theme")).toBe("dark");
    expect(window.localStorage.getItem("hst.user")).toBe("vera");
  });

  it("keeps the stored data of the same user", () => {
    window.localStorage.setItem("hst.user", "ada");
    window.localStorage.setItem("hst-workspace", "{}");
    claimUserStorage("ada");
    expect(window.localStorage.getItem("hst-workspace")).toBe("{}");
  });

  it("keeps stored data that has no recorded owner", () => {
    window.localStorage.setItem("hst-workspace", "{}");
    claimUserStorage("ada");
    expect(window.localStorage.getItem("hst-workspace")).toBe("{}");
    expect(window.localStorage.getItem("hst.user")).toBe("ada");
  });
});
