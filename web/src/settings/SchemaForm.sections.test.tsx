import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { SchemaForm } from "./SchemaForm";

it("saves connection and collection fields independently", async () => {
  const connection = vi.fn();
  const collection = vi.fn();
  render(
    <SchemaForm
      schema={{ type: "object", properties: {
        host: { type: "string", title: "Host" },
        password: { type: "string", title: "Password", writeOnly: true },
        interval_s: { type: "integer", title: "Interval" },
      } }}
      config={{ host: "router", interval_s: 60 }}
      mode="edit"
      submitLabel="Save"
      onSubmit={vi.fn()}
      onSubmitConnection={connection}
      onSubmitCollection={collection}
    />,
  );
  const user = userEvent.setup();
  await user.clear(screen.getByLabelText("Host"));
  await user.type(screen.getByLabelText("Host"), "router-2");
  await user.click(screen.getByRole("button", { name: "Save connection" }));
  expect(connection).toHaveBeenCalledWith({ host: "router-2" });
  expect(connection.mock.calls[0][0]).not.toHaveProperty("password");
  await user.click(screen.getByRole("button", { name: "Save collection" }));
  expect(collection).toHaveBeenCalledWith({ interval_s: 60 });
});
