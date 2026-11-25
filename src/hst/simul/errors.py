"""Named model errors raised by the simulation engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModelError:
    """One named fault of the model.

    `kind` is a stable identifier for grouping. `detail` is text for a person.
    `subject` is the name of the config object.
    """

    kind: str
    detail: str
    subject: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {"kind": self.kind, "detail": self.detail, "subject": self.subject}


@dataclass
class ErrorSink:
    """Collects model errors in report order and drops duplicates."""

    _seen: set[tuple[str, str, str | None]] = field(default_factory=set)
    _errors: list[ModelError] = field(default_factory=list)

    def report(self, kind: str, detail: str, subject: str | None = None) -> None:
        key = (kind, detail, subject)
        if key in self._seen:
            return
        self._seen.add(key)
        self._errors.append(ModelError(kind=kind, detail=detail, subject=subject))

    @property
    def errors(self) -> list[ModelError]:
        return list(self._errors)

    def as_dicts(self) -> list[dict[str, str | None]]:
        return [e.as_dict() for e in self._errors]
