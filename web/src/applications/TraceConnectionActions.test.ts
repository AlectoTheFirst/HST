import { expect, it } from "vitest";
import { catalogId } from "./TraceConnectionActions";

it("prefixes trace-derived catalog IDs that start with an address", () => {
  expect(catalogId("192.0.2.1 to 198.51.100.1")).toBe("connection-192-0-2-1-to-198-51-100-1");
  expect(catalogId("Checkout API")).toBe("checkout-api");
});
