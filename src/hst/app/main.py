"""The app factory. `hst serve` builds the app with a PgStore. Tests inject a fake store."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import re
from collections.abc import Iterable, Iterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

import neo4j.exceptions
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.datastructures import URL, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from hst import __version__
from hst.app import auth, security
from hst.app.api_docs import router as api_docs_router
from hst.app.body_limit import MIB, BodyLimit
from hst.app.crypto import GUIDANCE as SECRET_KEY_GUIDANCE
from hst.app.crypto import SecretKeyError
from hst.app.routes import health, setup
from hst.app.security import RateLimiter
from hst.core import Settings
from hst.core.snapshot import NoRun
from hst.worker import runtime as worker_runtime

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
# POST /api/auth/<slug>/acs (app/routes/sso.py) is the SAML ACS.
_CSRF_EXEMPT_PATH = re.compile(r"^/api/auth/[a-z0-9-]{1,64}/acs$")
# The MCP HTTP transport (routes/mcp_http.py) authenticates with a bearer token
# in the Authorization header.
_MCP_PATH = "/api/mcp"
log = logging.getLogger(__name__)


def _csrf_exempt(request: Request) -> bool:
    if request.method != "POST":
        return False
    path = request.url.path
    if _CSRF_EXEMPT_PATH.fullmatch(path):
        return True
    return path == _MCP_PATH and security.bearer_token(request.headers.get("authorization")) is not None


# React sets inline styles on elements.
SECURITY_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


def _security_headers(scope: Scope) -> dict[str, str]:
    url = URL(scope=scope)
    headers = {
        "Content-Security-Policy": SECURITY_CSP,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    if url.path.startswith("/api/"):
        headers["Cache-Control"] = "no-store"
    if url.scheme == "https":
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


class SecurityHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                headers = MutableHeaders(scope=message)
                for name, value in _security_headers(scope).items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _start_workers(app: FastAPI, settings: Settings, store: Any) -> list[asyncio.Task]:
    """Start the embedded scheduler and executor, when enabled."""
    tasks: list[asyncio.Task] = []
    app.state.scheduler = app.state.executor = None
    if settings.scheduler_enabled:
        loop = asyncio.get_running_loop()
        app.state.scheduler, app.state.executor = worker_runtime.build_loops(store, settings)
        tasks = [
            loop.create_task(worker_runtime.keep_scheduling(app.state.scheduler), name="scheduler"),
            loop.create_task(app.state.executor.run(), name="executor"),
        ]
    if settings.analysis_enabled and hasattr(store, "claim_analysis"):
        from hst.assessment.jobs import AnalysisWorker
        from hst.assessment.lifecycle import watch_assessments

        app.state.analysis_worker = AnalysisWorker(store, settings)
        tasks.append(asyncio.create_task(app.state.analysis_worker.run_forever(), name="analysis worker"))
        tasks.append(asyncio.create_task(watch_assessments(store, settings), name="assessment watch"))
    for task in tasks:
        task.add_done_callback(_log_ended)
    return tasks


def _log_ended(task: asyncio.Task) -> None:
    """Log a worker task that ended with an exception."""
    if task.cancelled():
        return
    error = task.exception()
    if error is not None:
        log.error("the %s task ended: %s: %s", task.get_name(), type(error).__name__, error)


async def _load_places(store: Any, path: Any, load: Any) -> None:
    """Run the start-up place load. A failure is logged, and the site address
    lookup stays empty."""
    try:
        await load(store, path)
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.getLogger("hst.geo_places").exception("geo places: the start-up load failed")


def _hst_bus(settings: Settings) -> Any:
    """The HST map event bus of this process, None without the `sidestore` extra."""
    try:
        from hst.map import events as hst_events
    except ImportError:
        return None
    bus = hst_events.LocalBus(settings.manifests_dir, settings.sidestore_dir)
    hst_events.set_default_bus(bus)
    return bus


def warn_if_no_proxy_is_trusted(settings: Settings) -> None:
    if (
        settings.public_url.startswith("https://")
        and not settings.tls_cert_file
        and not settings.forwarded_allow_ips.strip()
    ):
        log.warning("HST_PUBLIC_URL is HTTPS and HST_FORWARDED_ALLOW_IPS is empty")


def _make_lifespan(settings: Settings, store: Any, owns_store: bool):
    """Build the lifespan of the app. It opens the owned store on startup, runs
    the workers and tears both down on shutdown."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal store
        if owns_store:
            store = await worker_runtime.open_store(settings)
            app.state.store = store
            if not await store.list_users():
                logging.getLogger("hst.setup").warning(
                    "no accounts exist: first-run setup is open, and the first caller to "
                    "POST /api/setup becomes administrator"
                )
        from hst.app import sso_flow
        from hst.app.inventory import runtime as inventory_runtime

        warn_if_no_proxy_is_trusted(settings)
        await sso_flow.warn_if_public_url_missing(store, settings)
        await inventory_runtime.start(app)
        tasks = _start_workers(app, settings, store)
        hst_poll = app.state.hst_poll = (
            asyncio.create_task(app.state.hst_bus.run_poll()) if app.state.hst_bus is not None else None
        )
        if settings.geo_places_file is not None and hasattr(store, "replace_geo_places"):
            from hst.app.geo_places import load_bundled

            tasks.append(asyncio.create_task(_load_places(store, settings.geo_places_file, load_bundled)))
        app.state.worker_tasks = tasks
        # Every app process sweeps the AI turns whose process stopped, for every
        # value of SCHEDULER_ENABLED.
        from hst.app.ai import turns

        sweeper = app.state.turn_sweeper = turns.start_sweeper(store)
        try:
            yield
        finally:
            # A task that ended with an exception before the shutdown keeps it.
            # `gather` collects it, and the store is disposed in each case.
            ending = [side for side in (sweeper, hst_poll) if side is not None] + tasks
            for task in ending:
                task.cancel()
            try:
                await asyncio.gather(*ending, return_exceptions=True)
            finally:
                if owns_store:
                    await store.dispose()

    return lifespan


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    """The request body limit, the CSRF header check and the security response headers."""

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        exempt = _csrf_exempt(request)
        if request.method in MUTATING and not exempt and request.headers.get("X-HST-CSRF") != "1":
            return JSONResponse({"error": "missing CSRF header"}, status_code=403)
        return await call_next(request)

    # Starlette runs the middleware that is added last first.
    app.add_middleware(BodyLimit, max_bytes=settings.max_request_body_mb * MIB)
    app.add_middleware(SecurityHeaders)


def _install_exception_handlers(app: FastAPI) -> None:
    """Install the handlers that shape the response when a route handler raises."""

    @app.exception_handler(SecretKeyError)
    async def bad_secret_key(request: Request, exc: SecretKeyError):
        # The exception text of an unreadable HST_SECRET_KEY_FILE holds the file path.
        log.error("secret key error on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse({"error": SECRET_KEY_GUIDANCE}, status_code=500)

    @app.exception_handler(neo4j.exceptions.ServiceUnavailable)
    async def twin_unreachable(request: Request, exc: Exception):
        # The driver text holds the bolt address.
        log.error("twin unreachable on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse({"error": "twin unreachable"}, status_code=502)

    @app.exception_handler(NoRun)
    async def no_run(request: Request, exc: NoRun):
        return JSONResponse({"error": str(exc)}, status_code=404)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # The response holds no exception text.
        rid = uuid4().hex[:12]
        # A Starlette exception handler runs outside an `except` block.
        log.error("unhandled error [%s] %s %s", rid, request.method, request.url.path, exc_info=exc)
        # Starlette sends this response outside SecurityHeaders.
        return JSONResponse(
            {"error": "internal error", "request_id": rid},
            status_code=500,
            headers=_security_headers(request.scope),
        )

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(p) for p in first.get("loc", []) if p != "body")
        return JSONResponse(
            {"error": f"invalid request: {loc}: {first.get('msg', 'invalid')}"}, status_code=422
        )

    from fastapi import HTTPException
    from fastapi.exception_handlers import http_exception_handler

    @app.exception_handler(HTTPException)
    async def shaped(request: Request, exc: HTTPException):
        if isinstance(exc.detail, str):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        return await http_exception_handler(request, exc)


def _include_routers(app: FastAPI) -> None:
    """Every API router, all under /api."""
    app.include_router(auth.router, prefix="/api")
    app.include_router(health.router, prefix="/api")
    app.include_router(setup.router, prefix="/api")

    from hst.app import graphql as graphql_api
    from hst.app.routes import access_tokens as access_token_routes
    from hst.app.routes import ai as ai_routes
    from hst.app.routes import ai_conversations as ai_conversation_routes
    from hst.app.routes import auth_settings as auth_settings_routes
    from hst.app.routes import changes as changes_routes
    from hst.app.routes import changesim as changesim_routes
    from hst.app.routes import cypher as cypher_routes
    from hst.app.routes import debug_capture as debug_capture_routes
    from hst.app.routes import endpoints as endpoint_routes
    from hst.app.routes import equinix as equinix_routes
    from hst.app.routes import explore as explore_routes
    from hst.app.routes import geo_places as geo_place_routes
    from hst.app.routes import impact as impact_routes
    from hst.app.routes import jobs as job_routes
    from hst.app.routes import mcp_http as mcp_http_routes
    from hst.app.routes import mtu as mtu_routes
    from hst.app.routes import network_map as network_map_routes
    from hst.app.routes import path as path_routes
    from hst.app.routes import queries as query_routes
    from hst.app.routes import retention as retention_routes
    from hst.app.routes import runs as runs_routes
    from hst.app.routes import sdwan as sdwan_routes
    from hst.app.routes import site_graph as site_graph_routes
    from hst.app.routes import sites as site_routes
    from hst.app.routes import snapshots as snapshot_routes
    from hst.app.routes import sources as source_routes
    from hst.app.routes import sso as sso_routes
    from hst.app.routes import topology as topology_routes
    from hst.app.routes import users as user_routes

    # the HST map routes read tables written with the `sidestore` extra
    if importlib.util.find_spec("pyarrow") is not None:
        from hst.app.routes import hst as hst_routes

        app.include_router(hst_routes.router, prefix="/api")
    app.include_router(mtu_routes.router, prefix="/api")
    app.include_router(path_routes.router, prefix="/api")
    app.include_router(topology_routes.router, prefix="/api")
    app.include_router(endpoint_routes.router, prefix="/api")
    app.include_router(graphql_api.router(), prefix="/api")
    app.include_router(network_map_routes.router, prefix="/api")
    app.include_router(sdwan_routes.router, prefix="/api")
    app.include_router(equinix_routes.router, prefix="/api")
    app.include_router(query_routes.router, prefix="/api")
    app.include_router(cypher_routes.router, prefix="/api")
    app.include_router(explore_routes.router, prefix="/api")
    app.include_router(runs_routes.router, prefix="/api")
    app.include_router(debug_capture_routes.router, prefix="/api")
    app.include_router(job_routes.router, prefix="/api")
    app.include_router(user_routes.router, prefix="/api")
    app.include_router(source_routes.router, prefix="/api")
    app.include_router(ai_routes.router, prefix="/api")
    app.include_router(ai_conversation_routes.router, prefix="/api")
    app.include_router(access_token_routes.router, prefix="/api")
    app.include_router(mcp_http_routes.router, prefix="/api")
    mcp_http_routes.install(app)
    app.include_router(site_routes.router, prefix="/api")
    app.include_router(site_graph_routes.router, prefix="/api")
    app.include_router(geo_place_routes.router, prefix="/api")
    app.include_router(snapshot_routes.router, prefix="/api")
    app.include_router(sso_routes.router, prefix="/api")
    app.include_router(auth_settings_routes.router, prefix="/api")
    app.include_router(retention_routes.router, prefix="/api")
    app.include_router(impact_routes.router, prefix="/api")
    app.include_router(changes_routes.router, prefix="/api")
    app.include_router(changesim_routes.router, prefix="/api")
    from hst.app.routes import (
        ai_handoffs,
        analysis_sessions,
        application_generator,
        assessment_assistant,
        assessment_discovery,
        assessments,
        business_applications,
    )

    app.include_router(assessments.router, prefix="/api")
    app.include_router(assessment_discovery.router, prefix="/api")
    app.include_router(assessment_assistant.router, prefix="/api")
    app.include_router(analysis_sessions.router, prefix="/api")
    app.include_router(ai_handoffs.router, prefix="/api")
    # This router is included before the business application routes. Their
    # {application_id} paths match .../generations/{generation_id}.
    app.include_router(application_generator.router, prefix="/api")
    app.include_router(business_applications.router, prefix="/api")


def _mount_static(app: FastAPI, settings: Settings) -> None:
    """The built SPA, when a dist directory is present."""
    dist = settings.web_dist
    if not (dist / "index.html").is_file():
        return
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
    from starlette.convertors import PathConvertor, register_url_convertor
    from starlette.responses import Response

    class _SpaPath(PathConvertor):
        # The regex excludes every path under `api`, also the paths of routers that
        # app extensions register.
        regex = r"(?!api(?:/|$)).*"

    register_url_convertor("hst_spa", _SpaPath())

    # Asset filenames are content-hashed by the bundler.
    class _ImmutableAssets(StaticFiles):
        def file_response(self, *args: object, **kwargs: object) -> Response:
            response = super().file_response(*args, **kwargs)  # type: ignore[arg-type]
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return response

    app.mount("/assets", _ImmutableAssets(directory=dist / "assets"), name="assets")

    if (dist / "favicon.svg").is_file():

        @app.get("/favicon.svg", include_in_schema=False)
        def favicon() -> FileResponse:
            return FileResponse(dist / "favicon.svg", media_type="image/svg+xml")

    if (dist / "THIRD-PARTY-LICENSES.txt").is_file():

        @app.get("/THIRD-PARTY-LICENSES.txt", include_in_schema=False)
        def third_party_licenses() -> FileResponse:
            return FileResponse(dist / "THIRD-PARTY-LICENSES.txt", media_type="text/plain; charset=utf-8")

    @app.get("/{full_path:hst_spa}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        # `hst_spa` keeps a nonexistent /api/* path out of this catch-all.
        return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})


def _api_routes(routes: Iterable[Any]) -> Iterator[APIRoute]:
    """Each `APIRoute` in `routes`. An entry that FastAPI holds for an included
    router has the routes of that router in `original_router.routes`."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        included = getattr(getattr(route, "original_router", None), "routes", None)
        if included:
            yield from _api_routes(included)


def create_app(settings: Settings | None = None, store=None, *, register_inventory: bool = True) -> FastAPI:
    settings = settings or Settings()
    owns_store = store is None

    # Custom documentation routes require a session, including the schema.
    app = FastAPI(
        title="HST API",
        version=__version__,
        description=(
            "HST network digital twin API. Swagger UI uses the HST session cookie. Each "
            "operation checks the permissions of the signed-in account. POST, PUT, PATCH and "
            "DELETE requests require X-HST-CSRF: 1; Try it out adds it. Try it out sends real "
            "requests, mutations included."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_make_lifespan(settings, store, owns_store),
    )
    app.state.settings = settings
    app.state.store = store  # An owned store is None until the lifespan opens it.
    app.state.hst_bus = _hst_bus(settings)
    app.state.limiter = RateLimiter(settings.login_rate_limit, settings.login_rate_window_s)

    _install_middleware(app, settings)
    _install_exception_handlers(app)
    _include_routers(app)
    from hst.app.inventory import runtime as inventory_runtime

    if register_inventory:
        inventory_runtime.register(app)
    for route in _api_routes(app.routes):
        if not route.tags:
            route.tags = [route.endpoint.__module__.rsplit(".", 1)[-1].replace("_", " ")]
    app.include_router(api_docs_router, prefix="/api")
    _mount_static(app, settings)
    return app
