import { expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { BucketSection } from "./Buckets";
import { parseEvaluateServiceImpact } from "./assessImpact";

it("renders exact IPv6 counts without converting decimal text to a JavaScript number", () => {
  render(<BucketSection title="Sources" bucket={{
    count: 1, count_decimal: "1", address_count_decimal: "18446744073709551616",
    items: ["2001:db8::/64"], truncated: false,
  }} render={(item) => item} />);
  expect(screen.getByText("18446744073709551616 addresses")).toBeInTheDocument();
});

it("accepts exact counts beyond JSON safe integers and rejects missing count metadata", () => {
  const bucket = { count: null, count_decimal: "18446744073709551616", items: [], truncated: true };
  const value = {
    decided_change: { loss: bucket }, open_change: { loss: bucket },
    open: { before: bucket, after: bucket },
    request: {}, members: [], missing_evidence: [],
  };
  expect(parseEvaluateServiceImpact(JSON.stringify(value))).not.toBeNull();
  expect(parseEvaluateServiceImpact(JSON.stringify({
    ...value, decided_change: { loss: { ...bucket, count_decimal: undefined } },
  }))).toBeNull();
});
