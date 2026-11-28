"""The rule that a stored source credential follows no new endpoint and no
weaker TLS check.

A change of a field that `field_metadata` marks with an endpoint role is
refused while a stored secret stays in use and the request does not supply
it again.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from typing import Any

from pydantic import BaseModel

from hst import collectors as coll
from hst.app.inventory import field_metadata as fm

OTHER_ENDPOINT_DETAIL = "credentials required for an endpoint other than the stored one: "
WEAKER_TLS_DETAIL = "credentials required for a TLS check weaker than the stored one: "


class CredentialsRequired(Exception):
    """A change of the endpoint or of the TLS check keeps stored secrets.
    `kept` holds the dotted paths of those secrets."""

    def __init__(self, detail: str, kept: Iterable[str]):
        self.kept = sorted(kept)
        super().__init__(detail + ", ".join(self.kept))


def _default(model: type[BaseModel] | None, path: str) -> Any:
    head, _, rest = path.partition(".")
    field = model.model_fields.get(head) if model is not None else None
    if field is None or field.is_required():
        return None
    value = field.get_default(call_default_factory=True)
    for part in rest.split(".") if rest else ():
        value = getattr(value, part, None)
    return value


def _value(config: Mapping[str, Any] | None, path: str, model: type[BaseModel] | None) -> Any:
    """The value at `path`, or the default of the model when the config lacks it."""
    node: Any = config
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _default(model, path)
        node = node[part]
    return node


def _blank(value: Any) -> bool:
    return value is None or value == ""


def _weakens(role: str, old: Any, new: Any) -> bool:
    if role == fm.VERIFY:
        return old is not False and new is False
    if role == fm.TRUST:
        return not _blank(new) and new != old
    if role == fm.PIN:
        return not _blank(old) and new != old
    return False


def change(collector_type: str, before: Mapping[str, Any], after: Mapping[str, Any]) -> str | None:
    """OTHER_ENDPOINT_DETAIL when a destination field of `after` differs from
    `before`, WEAKER_TLS_DETAIL when a verify, trust or pin field weakens,
    None otherwise. An absent field takes the default of the config model,
    and None equals an empty string."""
    if collector_type not in fm.COLLECTORS:
        return None
    entry = coll.REGISTRY.get(collector_type)
    model = entry.ConfigModel if entry is not None else None
    roles = fm.endpoint_fields(collector_type)
    values = {path: (_value(before, path, model), _value(after, path, model)) for path in roles}
    for path, role in roles.items():
        old, new = values[path]
        if role == fm.DESTINATION and old != new and not (_blank(old) and _blank(new)):
            return OTHER_ENDPOINT_DETAIL
    for path, role in roles.items():
        if _weakens(role, *values[path]):
            return WEAKER_TLS_DETAIL
    return None


def require_secrets(
    collector_type: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    stored: Iterable[str],
    given: Collection[str],
) -> None:
    """Raise CredentialsRequired when `after` moves the endpoint or weakens the
    TLS check of `before`, and a path of `stored` is not in `given`.

    `stored` holds the dotted paths of the stored secrets that stay in use.
    `given` holds the paths that the request supplies with a non-empty value."""
    detail = change(collector_type, before, after)
    if detail is None:
        return
    kept = [path for path in stored if path not in given]
    if kept:
        raise CredentialsRequired(detail, kept)
