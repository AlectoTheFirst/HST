from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


def _identity(value: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError("identities must be nonempty strings without surrounding whitespace")


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    estate: str
    authority: str
    domain: str
    firewall_instance: str
    vrf: str
    address_family: Literal[4, 6]

    def __post_init__(self) -> None:
        for value in (self.estate, self.authority, self.domain, self.firewall_instance, self.vrf):
            _identity(value)
        if type(self.address_family) is not int or self.address_family not in (4, 6):
            raise ValueError("context address family must be 4 or 6")


@dataclass(frozen=True, slots=True)
class ObjectKey:
    authority: str
    domain: str
    uid: str

    def __post_init__(self) -> None:
        for value in (self.authority, self.domain, self.uid):
            _identity(value)


@dataclass(frozen=True, slots=True)
class Constant:
    value: bool

    def __post_init__(self) -> None:
        if type(self.value) is not bool:
            raise TypeError("predicate constant must be boolean")


@dataclass(frozen=True, slots=True)
class Atom:
    """An unsigned comparison of a header field.

    For `mask`, the bits that are 1 in `other` must match `value`.
    """

    field: str
    operation: Literal["eq", "range", "mask"]
    value: int
    other: int | None = None

    def __post_init__(self) -> None:
        _identity(self.field)
        if self.operation not in {"eq", "range", "mask"}:
            raise ValueError("unsupported atom operation")
        if type(self.value) is not int or self.value < 0:
            raise ValueError("atom values must be unsigned integers")
        if self.operation == "eq":
            if self.other is not None:
                raise ValueError("equality has no second operand")
        elif type(self.other) is not int or self.other < 0:
            raise ValueError("range/mask requires an unsigned second operand")
        if self.operation == "range" and self.other is not None and self.value > self.other:
            raise ValueError("reversed range")


@dataclass(frozen=True, slots=True)
class Unknown:
    code: str
    subject: str
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identity(self.code)
        _identity(self.subject)
        object.__setattr__(self, "evidence", tuple(self.evidence))


@dataclass(frozen=True, slots=True)
class Ref:
    key: ObjectKey


@dataclass(frozen=True, slots=True)
class AllOf:
    terms: tuple[Predicate, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "terms", tuple(self.terms))


@dataclass(frozen=True, slots=True)
class AnyOf:
    terms: tuple[Predicate, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "terms", tuple(self.terms))


@dataclass(frozen=True, slots=True)
class Not:
    term: Predicate


type Predicate = Constant | Atom | Unknown | Ref | AllOf | AnyOf | Not
type Action = Literal["permit", "deny", "return", "call", "unknown"]


@dataclass(frozen=True, slots=True)
class ObjectDefinition:
    key: ObjectKey
    revision: str
    predicate: Predicate
    complete: bool = True
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identity(self.revision)
        if type(self.complete) is not bool:
            raise TypeError("object completeness must be explicit boolean")
        object.__setattr__(self, "evidence", tuple(self.evidence))


@dataclass(frozen=True, slots=True)
class Rule:
    uid: str
    predicate: Predicate
    action: Action
    enabled: bool = True
    called_layer: str | None = None
    # An empty tuple is every installation, and None is unknown applicability.
    install_targets: tuple[str, ...] | None = ()
    evidence: tuple[str, ...] = ()
    source_position: tuple[int, ...] = ()
    implied: bool = False

    def __post_init__(self) -> None:
        _identity(self.uid)
        if self.action not in {"permit", "deny", "return", "call", "unknown"}:
            raise ValueError("unsupported rule action; preserve it with action='unknown'")
        if type(self.enabled) is not bool:
            raise TypeError("rule enabled state must be explicit boolean")
        if (self.action == "call") != (self.called_layer is not None):
            raise ValueError("only a call must specify a called layer")
        if self.called_layer is not None:
            _identity(self.called_layer)
        if self.install_targets is not None:
            object.__setattr__(self, "install_targets", tuple(self.install_targets))
            for target in self.install_targets:
                _identity(target)
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "source_position", tuple(self.source_position))


@dataclass(frozen=True, slots=True)
class Layer:
    uid: str
    rules: tuple[Rule, ...]
    default: Literal["permit", "deny", "return", "unknown"]

    def __post_init__(self) -> None:
        _identity(self.uid)
        object.__setattr__(self, "rules", tuple(self.rules))
        if self.default not in {"permit", "deny", "return", "unknown"}:
            raise ValueError("layer default must be explicit")
        if len({rule.uid for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate rule UID within layer")


@dataclass(frozen=True, slots=True)
class Policy:
    uid: str
    revision: str
    context: ExecutionContext
    layers: tuple[Layer, ...]
    ordered_layers: tuple[str, ...]
    objects: tuple[ObjectDefinition, ...] = ()
    installation: Predicate = Unknown("INSTALLATION_UNKNOWN", "policy")
    semantic_profile: str = "explicit-filter-v1"
    evidence: tuple[str, ...] = ()
    manifest_digest: str = ""
    configured_revision: str = ""
    installed_revision: str = ""
    collection_window: tuple[str, str] = ("", "")
    ir_version: int = 1

    def __post_init__(self) -> None:
        for value in (self.uid, self.revision, self.semantic_profile):
            _identity(value)
        for name in ("layers", "ordered_layers", "objects", "evidence", "collection_window"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if self.ir_version != 1 or type(self.ir_version) is not int:
            raise ValueError("unsupported policy IR version")
        if not self.ordered_layers:
            raise ValueError("a policy needs an explicit ordered layer")
        if len({layer.uid for layer in self.layers}) != len(self.layers):
            raise ValueError("duplicate layer UID")
        if len({obj.key for obj in self.objects}) != len(self.objects):
            raise ValueError("duplicate qualified object identity")
