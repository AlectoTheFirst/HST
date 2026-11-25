"""The role to permission-set table in hst.app.permissions."""

from hst.app.permissions import PERMISSIONS, ROLE_PERMISSIONS, permissions_for


def test_the_permission_vocabulary_is_exactly_these_names():
    assert {
        "graph.read",
        "agent.ask",
        "cypher.run",
        "runs.manage",
        "interfaces.read",
        "sites.write",
        "inventory.write",
        "changes.write",
        "sources.write",
        "graph.purge",
        "users.manage",
        "settings.auth",
        "settings.ai",
        "settings.retention",
    } == PERMISSIONS


def test_viewer_permissions():
    assert ROLE_PERMISSIONS["viewer"] == {"graph.read", "agent.ask"}


def test_operator_permissions():
    assert ROLE_PERMISSIONS["operator"] == {
        "graph.read",
        "agent.ask",
        "cypher.run",
        "runs.manage",
        "sites.write",
        "inventory.write",
        "changes.write",
        "interfaces.read",
    }


def test_admin_holds_every_permission():
    assert ROLE_PERMISSIONS["admin"] == PERMISSIONS


def test_the_roles_are_exactly_viewer_operator_admin_in_rank_order():
    """Insertion order carries the rank the frontend's atLeast-style checks
    assume: viewer below operator below admin."""
    assert list(ROLE_PERMISSIONS) == ["viewer", "operator", "admin"]


def test_each_role_is_a_strict_subset_of_the_next():
    viewer, operator, admin = (ROLE_PERMISSIONS[r] for r in ("viewer", "operator", "admin"))
    assert viewer < operator < admin


def test_every_role_references_only_declared_permission_names():
    for role, granted in ROLE_PERMISSIONS.items():
        assert granted <= PERMISSIONS, f"{role} grants undeclared permissions: {granted - PERMISSIONS}"


def test_every_permission_is_granted_to_at_least_one_role():
    granted = frozenset().union(*ROLE_PERMISSIONS.values())
    assert granted == PERMISSIONS


def test_role_sets_are_immutable():
    for granted in ROLE_PERMISSIONS.values():
        assert isinstance(granted, frozenset)


def test_permissions_for_resolves_known_roles():
    for role, granted in ROLE_PERMISSIONS.items():
        assert permissions_for(role) == granted


def test_permissions_for_an_unknown_role_is_empty_not_an_error():
    assert permissions_for("root") == frozenset()
    assert permissions_for("") == frozenset()
