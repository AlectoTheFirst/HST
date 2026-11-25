"""What carry-forward does for an object a scope that did not collect shares
with a load of this run (core/cycle.py `carry_forward`):

- the assertions of that scope's source on it are laid over the fresh write,
  as a second source's load lays them (`_carry_contributions`,
  core/loader.py `assertion_props`), when the parent run records the scope
  as a writer of the object (its first writer, a scope an earlier carry laid
  over it, or the writer of one of its relationships) or the run asked the
  source nothing; never when the fresh write already names the source, and
  never over an object under another anchor;
- a relationship that scope wrote between two objects the run wrote afresh
  comes forward;
- an object a scope carried as unchanged is recorded as having written, whose
  uid this run's loads wrote under another anchor, fails the run, as a load
  of that scope would have (`_check_carry_anchors`); one of a scope that
  failed does not.

The store is the one tests/test_carry_forward_stream.py answers the carry's
statements with. tests/test_carry_contributions_db.py runs the same cases on
Neo4j, against the run loading both sources gives."""

from __future__ import annotations

import pytest
from tests.test_carry_forward_stream import NEW, PREV, _Node, _Store

from hst.core import cycle as cyclemod
from hst.core.cycle import CARRIED_SCOPES
from hst.core.labels import CycleIdentityCollision
from hst.core.loader import encode_assertion

APIC, NXOS = "apic:fab1", "nxos:leaf1"
UID = "dev:SN1"
NEXT = 300
BOTH_ROLES = sorted([encode_assertion("apic", "fab1", "leaf"), encode_assertion("nxos", "leaves", "switch")])


def _shared(store: _Store, *, recorded: bool) -> None:
    """The parent run's leaf, first written by the APIC scope and, when
    `recorded`, by the NX-OS scope too, and the new run's fresh NX-OS write."""
    props = {"uid": UID, "collection_ts": PREV, "_scope": APIC, "name": "leaf1", "role": "leaf"}
    if recorded:
        props |= {
            "_sources": ["fab1", "leaves"],
            "role": "switch",
            "_assert.role": BOTH_ROLES,
            "_assert.name": sorted(
                [encode_assertion("apic", "fab1", "leaf1"), encode_assertion("nxos", "leaves", "leaf1")]
            ),
        }
    else:
        props["_sources"] = ["fab1"]
    store.node(["Obj", "Device", "Phys"], **props)
    store.node(
        ["Obj", "Device", "Phys"],
        uid=UID,
        collection_ts=NEW,
        _scope=NXOS,
        _sources=["leaves"],
        name="leaf1",
        role="switch",
        carried=False,
    )


def _carry(store: _Store, reason: str = "failed", **kw: object) -> dict[str, int]:
    return cyclemod.carry_forward(
        store, PREV, NEW, ["fab1"], scopes={APIC: reason}, collected=[NXOS], unasked=[], **kw
    )


def _fresh(store: _Store) -> dict[str, object]:
    node = store._find(UID, NEW)
    assert node is not None
    return node.props


@pytest.mark.parametrize("recorded", [True, False], ids=["two-writers", "one-writer"])
def test_a_carried_scope_keeps_its_assertions_on_an_object_another_load_wrote(recorded: bool) -> None:
    store = _Store()
    _shared(store, recorded=recorded)

    _carry(store)

    fresh = _fresh(store)
    assert fresh["_sources"] == ["leaves", "fab1"]
    assert fresh["_assert.role"] == BOTH_ROLES
    assert fresh["_assert.name"] == sorted(
        [encode_assertion("apic", "fab1", "leaf1"), encode_assertion("nxos", "leaves", "leaf1")]
    )
    # the device's own answer outranks the controller's (core/loader.py
    # DEFAULT_PRECEDENCE), whichever wrote first
    assert fresh["role"] == "switch"
    assert fresh["carried"] is False
    assert len([n for n in store.nodes if n.props.get("collection_ts") == NEW]) == 1


def test_a_fresh_write_that_names_the_carried_source_is_left_alone() -> None:
    """Two devices of one fleet share its source row: the collected one's
    write is that source's answer for the run."""
    store = _Store()
    _shared(store, recorded=True)
    _fresh(store)["_sources"] = ["fab1", "leaves"]
    before = dict(_fresh(store))

    _carry(store)

    assert _fresh(store) == before


def test_a_carried_copy_takes_no_contribution() -> None:
    store = _Store()
    _shared(store, recorded=True)
    _fresh(store)["carried"] = True
    before = dict(_fresh(store))

    _carry(store)

    assert _fresh(store) == before


def _device(store: _Store, cts: int, scope: str, sources: list[str], **props: object) -> _Node:
    return store.node(
        ["Obj", "Device", "Phys"],
        uid=UID,
        collection_ts=cts,
        _scope=scope,
        _sources=sources,
        carried=False,
        **props,
    )


def test_a_scope_that_stays_unchanged_keeps_its_assertions_run_after_run() -> None:
    """The fresh write names the collected scope as the object's first
    writer, so the second run finds the carried scope through the pair the
    first run's carry laid."""
    store = _Store()
    _shared(store, recorded=True)
    _carry(store, cyclemod.UNCHANGED)
    _device(store, NEXT, NXOS, ["leaves"], name="leaf1", role="switch")

    cyclemod.carry_forward(
        store, NEW, NEXT, ["fab1"], scopes={APIC: cyclemod.UNCHANGED}, collected=[NXOS], unasked=[]
    )

    for cts in (NEW, NEXT):
        node = store._find(UID, cts)
        assert node is not None
        assert node.props["_sources"] == ["leaves", "fab1"]
        assert node.props["_assert.role"] == BOTH_ROLES
        assert node.props["role"] == "switch"
        assert node.props[CARRIED_SCOPES] == ["fab1/apic:fab1"]


def _second_writer(store: _Store, *, edge: bool) -> None:
    """The parent run's leaf, first written by the controller and then by
    the device, whose interface it holds; the new run's controller write."""
    old = _device(
        store,
        PREV,
        APIC,
        ["fab1", "leaves"],
        name="leaf1",
        role="switch",
        **{"_assert.role": BOTH_ROLES},
    )
    iface = store.node(
        ["Obj", "Interface", "L2"],
        uid="if:SN1:eth1",
        collection_ts=PREV,
        _scope=NXOS,
        _sources=["leaves"],
        name="eth1",
        carried=False,
    )
    if edge:
        store.rel("ON", iface, old, _scope=NXOS)
    _device(store, NEW, APIC, ["fab1"], name="leaf1", role="leaf")


def test_a_scope_that_wrote_an_object_second_is_found_through_its_relationship() -> None:
    store = _Store()
    _second_writer(store, edge=True)

    cyclemod.carry_forward(
        store, PREV, NEW, ["leaves"], scopes={NXOS: cyclemod.UNCHANGED}, collected=[APIC], unasked=[]
    )

    fresh = _fresh(store)
    assert fresh["_sources"] == ["fab1", "leaves"]
    assert fresh["_assert.role"] == BOTH_ROLES
    assert fresh["role"] == "switch"
    assert fresh[CARRIED_SCOPES] == ["leaves/nxos:leaf1"]
    _nodes, rels = store.state(NEW)
    assert len(rels) == 1 and "'ON', 'if:SN1:eth1', 'dev:SN1'" in rels[0]


def test_a_source_nothing_records_as_a_writer_lays_nothing() -> None:
    """Without the relationship, nothing the parent run holds says that the
    scope which did not collect wrote the leaf: its source may have written
    it through a scope that collected."""
    store = _Store()
    _second_writer(store, edge=False)

    cyclemod.carry_forward(
        store, PREV, NEW, ["leaves"], scopes={NXOS: cyclemod.UNCHANGED}, collected=[APIC], unasked=[]
    )

    assert _fresh(store)["_sources"] == ["fab1"]
    assert not any(k.startswith("_assert.") for k in _fresh(store))


def test_a_source_whose_collected_scope_dropped_an_object_lays_nothing_over_it() -> None:
    """leaf1 answered without the port. leaf2 of the same source skipped its
    load as unchanged, but no record says it wrote the port."""
    store = _Store()
    port = "dev:SN1/port/eth1-5"
    old_port = store.node(
        ["Obj", "Port", "Phys"],
        uid=port,
        collection_ts=PREV,
        _scope=APIC,
        _sources=["fab1", "leaves"],
        name="eth1/5",
        **{
            "_assert.name": sorted(
                [
                    encode_assertion("apic", "fab1", "eth1/5"),
                    encode_assertion("nxos", "leaves", "Ethernet1/5"),
                ]
            )
        },
    )
    old_dev = _device(store, PREV, NXOS, ["leaves"], name="leaf1", role="switch")
    store.rel("HAS_PORT", old_dev, old_port, _scope=NXOS)
    _device(store, NEW, NXOS, ["leaves"], name="leaf1", role="switch")
    store.node(
        ["Obj", "Port", "Phys"],
        uid=port,
        collection_ts=NEW,
        _scope=APIC,
        _sources=["fab1"],
        name="eth1/5",
        carried=False,
    )

    cyclemod.carry_forward(
        store,
        PREV,
        NEW,
        ["leaves"],
        scopes={"nxos:leaf2": cyclemod.UNCHANGED},
        collected=[APIC, NXOS],
        unasked=[],
    )

    node = store._find(port, NEW)
    assert node is not None and node.props["_sources"] == ["fab1"]
    assert "_assert.name" not in node.props


def test_a_source_this_run_asked_nothing_keeps_its_assertions() -> None:
    """No scope of the controller's source is named at all: the run did not
    ask it, which proves nothing about the leaf, as it proves nothing about a
    device dropped from its inventory (`_READ_CARRY_NODES`, case 4)."""
    store = _Store()
    _device(
        store,
        PREV,
        NXOS,
        ["leaves", "fab1"],
        name="leaf1",
        role="switch",
        **{"_assert.role": BOTH_ROLES},
    )
    _device(store, NEW, NXOS, ["leaves"], name="leaf1", role="switch")

    cyclemod.carry_forward(store, PREV, NEW, ["fab1"], scopes={}, collected=[NXOS], unasked=["fab1"])

    fresh = _fresh(store)
    assert fresh["_sources"] == ["leaves", "fab1"]
    assert fresh["_assert.role"] == BOTH_ROLES
    assert CARRIED_SCOPES not in fresh


def _pair(store: _Store, cts: int, scope: str, sources: list[str]) -> tuple[_Node, _Node]:
    ends = []
    for uid in ("dev:A", "dev:B"):
        ends.append(
            store.node(
                ["Obj", "Device", "Phys"],
                uid=uid,
                collection_ts=cts,
                _scope=scope,
                _sources=sources,
                role="leaf",
                carried=False,
            )
        )
    return ends[0], ends[1]


def test_an_edge_the_carried_scope_wrote_between_two_fresh_objects_comes_forward() -> None:
    """The controller's link between two leaves the device source also
    writes. An edge of a scope that collected, between the same two, is a
    removal."""
    store = _Store()
    a, b = _pair(store, PREV, APIC, ["fab1", "leaves"])
    store.rel("CONNECTED_TO", a, b, collected_at=PREV - 10, _scope=APIC)
    store.rel("L3_ADJACENT", a, b, _scope=NXOS)
    _pair(store, NEW, NXOS, ["leaves"])

    counts = cyclemod.carry_forward(
        store, PREV, NEW, ["fab1"], scopes={APIC: cyclemod.UNCHANGED}, collected=[NXOS], unasked=[]
    )

    links = [r for r in store.rels if r.props.get("collection_ts") == NEW]
    assert counts["rels"] == 1
    assert [(r.type, r.start.props["uid"], r.end.props["uid"]) for r in links] == [
        ("CONNECTED_TO", "dev:A", "dev:B")
    ]
    assert (links[0].props["carried"], links[0].props["carried_reason"]) == (True, cyclemod.UNCHANGED)
    assert links[0].props["last_seen_ts"] == PREV - 10


def test_a_field_only_the_carried_source_asserted_is_written_on_the_fresh_object() -> None:
    """A load of the controller writes the field itself, as `SET n +=
    row.props` does, beside its single assertion."""
    store = _Store()
    _device(store, PREV, APIC, ["fab1"], name="leaf1", role="leaf", apic_role="leaf")
    _device(store, NEW, NXOS, ["leaves"], name="leaf1", role="switch", os="10.3")

    _carry(store)

    fresh = _fresh(store)
    assert fresh["apic_role"] == "leaf"
    assert fresh["_assert.apic_role"] == [encode_assertion("apic", "fab1", "leaf")]
    assert fresh["os"] == "10.3"
    assert fresh["_assert.os"] == [encode_assertion("nxos", "leaves", "10.3")]
    assert fresh["role"] == "switch"


def test_a_carried_copy_lays_no_carry_stamp_as_an_assertion() -> None:
    """The parent run's leaf is itself a carried copy: its `carried_reason`
    and `last_seen_ts` are the carry's, not the controller's answer."""
    store = _Store()
    _device(
        store,
        PREV,
        APIC,
        ["fab1"],
        name="leaf1",
        role="leaf",
        collected_at=50,
        carried_reason="failed",
        last_seen_ts=50,
    )
    store._find(UID, PREV).props["carried"] = True  # type: ignore[union-attr]
    _device(store, NEW, NXOS, ["leaves"], name="leaf1", role="switch")

    _carry(store)

    fresh = _fresh(store)
    assert fresh["_sources"] == ["leaves", "fab1"]
    assert fresh["_assert.role"] == BOTH_ROLES
    assert not {"carried_reason", "last_seen_ts", "_assert.carried_reason", "_assert.last_seen_ts"} & set(
        fresh
    )


def _anchored(store: _Store, carried: tuple[str, str], fresh: tuple[str, str], **laid: object) -> None:
    """The parent run's prefix of `carried` (scope, source) under vrf:a, and
    the new run's of `fresh` under vrf:b."""
    store.node(
        ["Obj", "Prefix", "L3"],
        uid="pfx:10.0.0.0/8",
        collection_ts=PREV,
        _scope=carried[0],
        _sources=[carried[1]],
        anchor="vrf:a",
        **laid,
    )
    store.node(
        ["Obj", "Prefix", "L3"],
        uid="pfx:10.0.0.0/8",
        collection_ts=NEW,
        _scope=fresh[0],
        _sources=[fresh[1]],
        anchor="vrf:b",
        carried=False,
    )


def test_an_unchanged_scope_whose_uid_was_written_under_another_anchor_fails_the_run() -> None:
    store = _Store()
    _anchored(store, (APIC, "fab1"), (NXOS, "leaves"))

    with pytest.raises(CycleIdentityCollision, match=r"'pfx:10\.0\.0\.0/8'.*anchor='vrf:b'.*anchor='vrf:a'"):
        _carry(store, reason=cyclemod.UNCHANGED)
    assert not store.chunks


def test_an_unchanged_scope_an_earlier_carry_laid_is_checked_as_a_writer() -> None:
    store = _Store()
    _anchored(store, ("iosxe:r1", "edge"), (NXOS, "leaves"), **{CARRIED_SCOPES: ["fab1/apic:fab1"]})

    with pytest.raises(
        CycleIdentityCollision, match=r"unchanged scope apic:fab1 holds it with anchor='vrf:a'"
    ):
        _carry(store, reason=cyclemod.UNCHANGED)
    assert not store.chunks


@pytest.mark.parametrize(
    ("carried", "fresh"),
    [((APIC, "fab1"), (NXOS, "leaves")), ((NXOS, "leaves"), (APIC, "fab1"))],
    ids=["configured-carried", "observed-carried"],
)
@pytest.mark.parametrize("reason", ["failed", "not-run", "cancelled"])
def test_a_scope_that_did_not_answer_yields_to_the_fresh_write(
    reason: str, carried: tuple[str, str], fresh: tuple[str, str]
) -> None:
    """Whichever of the two outranks the other: the stale anchor names
    another object, so nothing of it is laid over the fresh one."""
    store = _Store()
    _anchored(store, carried, fresh)

    cyclemod.carry_forward(
        store, PREV, NEW, [carried[1]], scopes={carried[0]: reason}, collected=[fresh[0]], unasked=[]
    )

    node = store._find("pfx:10.0.0.0/8", NEW)
    assert node is not None
    assert (node.props["anchor"], node.props["_sources"]) == ("vrf:b", [fresh[1]])
    assert not any(k.startswith("_assert.") for k in node.props)
