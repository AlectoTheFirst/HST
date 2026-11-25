"""The per-request context of the GraphQL endpoint. It holds the caller, the
run that the request reads and the batched reads.

A request authenticates with the session cookie (app/auth.py) or with a
personal access token in `Authorization: Bearer <token>`, as `/api/mcp` does
(routes/mcp_http.py). If the header is present, the token is the only
credential. A request without a credential, or with a token that is unknown,
expired or of a disabled user, gets a 401 before GraphQL runs.

The run. The first root field that runs resolves the run once through
`snapshot.resolve`. It resolves the run of its `run` argument or of its
cursor, else the current run. Every later field of the request reads that
run. A root field that gives another run raises an error. Every read takes
the `$snap` of the run.

Batching. Every object and every child list is read through a DataLoader of
this request. A page of N objects with a nested field costs one Cypher read
per level. A read runs in a worker thread with its own session from the
driver pool of the process.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request
from graphql import GraphQLError
from strawberry.dataloader import DataLoader
from strawberry.fastapi import BaseContext

from hst.app import auth, security
from hst.app.permissions import permissions_for
from hst.core import db as dbmod
from hst.core import entity_read
from hst.core import snapshot as snapshotmod

_session = dbmod.session  # seam for tests

_UNAUTHORIZED = {"WWW-Authenticate": 'Bearer realm="hst"'}


async def authenticate(request: Request) -> Any:
    """Returns the user of the bearer token if the request sends one, else the
    user of the session cookie. Raises a 401 if neither gives a user."""
    token = security.bearer_token(request.headers.get("authorization"))
    if request.headers.get("authorization") is not None and token is None:
        raise HTTPException(
            401, detail="the authorization header is not a bearer token", headers=_UNAUTHORIZED
        )
    if token is not None:
        found = await request.app.state.store.get_access_token_user(
            security.token_hash(token), datetime.now(UTC)
        )
        if found is None or found[1].disabled:
            raise HTTPException(401, detail="the token is unknown, revoked or expired", headers=_UNAUTHORIZED)
        return found[1]
    return await auth.current_user(request, request.cookies.get(auth.COOKIE))


class GraphContext(BaseContext):
    """One request's caller, run and loaders."""

    def __init__(self, settings: Any, user: Any) -> None:
        super().__init__()
        self.settings = settings
        self.user = user
        self.permissions = permissions_for(user.role)
        self._lock = asyncio.Lock()
        self._snapshot: snapshotmod.Snapshot | None = None
        self.rows: dict[str, DataLoader[str, dict[str, Any] | None]] = {
            kind: DataLoader(load_fn=self._rows_loader(kind)) for kind in entity_read.ROWS
        }
        self.children: dict[tuple[str, str], DataLoader[tuple[str, int], list[str]]] = {
            pair: DataLoader(load_fn=self._children_loader(*pair)) for pair in entity_read.CHILDREN
        }

    # --- the run -----------------------------------------------------------------------

    @property
    def snapshot(self) -> snapshotmod.Snapshot:
        if self._snapshot is None:
            raise GraphQLError("no run is resolved for this request")
        return self._snapshot

    @property
    def snap(self) -> Any:
        return snapshotmod.snap_param(self.snapshot.cts)

    async def pin(self, run: str | None, cursor_run: int | None = None) -> snapshotmod.Snapshot:
        """Returns the run of this request. The first call resolves it. A later
        call that gives another run raises a GraphQLError."""
        try:
            named = snapshotmod.parse_snapshot_id(run)
        except ValueError as exc:
            raise GraphQLError(str(exc)) from exc
        if cursor_run is not None:
            if named is not None and named != cursor_run:
                raise GraphQLError("the cursor belongs to another run than the run argument")
            named = cursor_run
        async with self._lock:
            if self._snapshot is None:
                self._snapshot = await asyncio.to_thread(self._resolve, named)
            elif named is not None and named != self._snapshot.cts:
                raise GraphQLError(f"this request reads run {self._snapshot.cts}; one request reads one run")
        return self._snapshot

    def _resolve(self, named: int | None) -> snapshotmod.Snapshot:
        with _session(self.settings) as s:
            if named is not None:
                try:
                    snapshotmod.require_retained(s, named)
                except ValueError as exc:
                    raise GraphQLError(f"unknown run: {named}") from exc
            return snapshotmod.resolve(s, self.settings, named)

    # --- reads -------------------------------------------------------------------------

    def read(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """`fn(session, *args, **kwargs)` on a session of its own."""
        with _session(self.settings) as s:
            return fn(s, *args, **kwargs)

    async def in_thread(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(self.read, fn, *args, **kwargs)

    def _rows_loader(self, kind: str) -> Any:
        async def load(uids: list[str]) -> list[dict[str, Any] | None]:
            rows = await self.in_thread(entity_read.read_rows, kind, list(uids), snap=self.snap)
            return [rows.get(u) for u in uids]

        return load

    def _children_loader(self, parent: str, child: str) -> Any:
        async def load(keys: list[tuple[str, int]]) -> list[list[str]]:
            by_first: dict[int, list[str]] = defaultdict(list)
            for uid, first in keys:
                by_first[first].append(uid)
            found: dict[tuple[str, int], list[str]] = {}
            for first, uids in by_first.items():
                got = await self.in_thread(
                    entity_read.read_children, parent, child, uids, first=first, snap=self.snap
                )
                found |= {(u, first): got.get(u, []) for u in uids}
            return [found[k] for k in keys]

        return load


async def graph_context(request: Request) -> GraphContext:
    """The context getter of the GraphQL router."""
    user = await authenticate(request)
    return GraphContext(request.app.state.settings, user)
