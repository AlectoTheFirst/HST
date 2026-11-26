import { conditionSentence } from "../../assessments/types";
import { toCondition } from "../ApplicationEditor";
import type { ApplicationConnection, BusinessApplicationDefinition } from "../types";

/** The protocol and destination ports of a connection, such as `tcp/443`. */
export function portText(connection: ApplicationConnection): string {
  const protocol = connection.protocol ?? "any";
  const ports = connection.destination_ports ?? [];
  return ports.length ? `${protocol}/${ports.join(", ")}` : protocol;
}

export function groupName(definition: BusinessApplicationDefinition, id: string): string {
  return definition.groups.find((group) => group.id === id)?.name ?? id;
}

/** The required destination: the member name for a single member, else the condition sentence. */
export function requiredText(definition: BusinessApplicationDefinition, connection: ApplicationConnection): string {
  const condition = connection.destination_condition;
  if (condition.kind === "member") {
    const member = definition.groups
      .find((group) => group.id === connection.destination)
      ?.members.find((item) => item.id === condition.member);
    return member?.name ?? condition.member ?? "";
  }
  return conditionSentence(toCondition(condition));
}

export function serviceOf(definition: BusinessApplicationDefinition, connectionId: string) {
  return definition.services.find((service) => service.connection_ids.includes(connectionId));
}
