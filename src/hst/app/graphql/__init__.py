"""The read-only GraphQL endpoint at `/api/graphql`."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.routing import APIRoute

PATH = "/api/graphql"


def router() -> APIRouter:
    """The Strawberry FastAPI router, POST only, mounted under /api."""
    from strawberry.fastapi import GraphQLRouter

    from hst.app.graphql.context import graph_context
    from hst.app.graphql.schema import schema

    gql: GraphQLRouter = GraphQLRouter(
        schema,
        path="/graphql",
        graphql_ide=None,
        allow_queries_via_get=False,
        subscription_protocols=(),
        context_getter=graph_context,
        tags=["graphql"],
    )
    gql.routes = [r for r in gql.routes if isinstance(r, APIRoute) and r.methods == {"POST"}]
    return gql
