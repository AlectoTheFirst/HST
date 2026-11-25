"""The model client and the ask queue shared by every AI surface.

`ModelClient` reads the stored provider settings, decrypts the credentials,
builds the adapter for the configured provider and runs one model turn or a
probe. The ask route, the assessment assistant and the admin probe use it.

The module also holds the gate that bounds concurrent asks, the queue cap and
the per-user cap.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hst.app import crypto, tls
from hst.app.agent import base as agent_base
from hst.app.agent import registry
from hst.app.crypto import SecretKeyError, decrypt_secrets

if TYPE_CHECKING:
    from fastapi import Request

    from hst.app.agent.base import AgentAdapter, AgentAnswer, StepCallback
    from hst.app.agent.budget import AskBudget
    from hst.app.agent.tools import Tool

MAX_CONCURRENT_ASKS = 4
_ask_gate = asyncio.Semaphore(MAX_CONCURRENT_ASKS)

# The bound of the queue behind `_ask_gate`.
MAX_QUEUED_ASKS = MAX_CONCURRENT_ASKS * 4
# The per-user share of the process-wide queue bound.
MAX_ASKS_PER_USER = 2


async def read_settings(store: Any, app_settings: Any) -> tuple[dict[str, Any], dict[str, str], Any, bool]:
    """Stored settings merged over the defaults, the decrypted credentials, when
    the row last changed (None before anything is stored), and whether the
    stored blob failed to decrypt under the current key.

    The DEK is resolved before any row blob is decrypted. A blob that does not
    decrypt under a good key gives absent credentials and a True last element.
    """
    key = crypto.dek(app_settings)
    return decode_settings(await store.get_setting(registry.SETTINGS_KEY), key)


def decode_settings(row: Any, key: str) -> tuple[dict[str, Any], dict[str, str], Any, bool]:
    """`read_settings` for the stored row `row` and the data key `key`."""
    settings = registry.merged(row.value if row else None)
    secrets: dict[str, str] = {}
    unreadable = False
    if row and row.secrets:
        try:
            secrets = decrypt_secrets(key, row.secrets)
        except SecretKeyError:
            unreadable = True
    return settings, secrets, row.updated_at if row else None, unreadable


async def _load(request: Request) -> tuple[dict[str, Any], dict[str, str], Any, bool]:
    """`read_settings` for the app that serves `request`."""
    return await read_settings(request.app.state.store, request.app.state.settings)


@dataclass
class TurnRequest:
    """One model turn. `messages`, when given, replaces `history` and the
    question as the seeded conversation. `on_step` receives each tool step as
    the tool returns."""

    question: str
    system: str
    tools: list[Tool] = field(default_factory=list)
    history: Sequence[Mapping[str, str]] = ()
    messages: Sequence[Mapping[str, Any]] | None = None
    budget: AskBudget | None = None
    on_step: StepCallback | None = None


class ModelClient:
    """The configured provider, model and credentials behind one object.

    `config` is the merged AI settings row (`registry.merged`), `secrets` the
    decrypted credentials and `trust` the resolved TLS trust for the provider.
    The adapter is built on first use and reused for the client's lifetime.
    """

    def __init__(
        self, config: dict[str, Any], secrets: dict[str, str], trust: tls.Trust | None = None
    ) -> None:
        self.config = config
        self.secrets = secrets
        self.trust = trust
        self._adapter: AgentAdapter | None = None

    @classmethod
    async def from_store(cls, store: Any, app_settings: Any) -> ModelClient:
        config, secrets, _, _ = await read_settings(store, app_settings)
        return cls(config, secrets, tls.resolve(app_settings, config.get("options", {})))

    @property
    def provider(self) -> str:
        return str(self.config["provider"])

    @property
    def model(self) -> str:
        return str(self.config["model"])

    def enabled(self) -> bool:
        return bool(self.config["enabled"])

    def configured(self) -> bool:
        return registry.is_configured(self.config, self.secrets)

    def available(self) -> bool:
        """Whether the agent is turned on and has credentials."""
        return self.enabled() and self.configured()

    def adapter(self) -> AgentAdapter:
        """The provider adapter. Raises `AgentError` for an unknown provider."""
        if self._adapter is None:
            self._adapter = agent_base.build(
                self.provider, self.secrets, self.config.get("options", {}), self.trust
            )
        return self._adapter

    def run(self, turn: TurnRequest) -> AgentAnswer:
        """Run one turn with the configured model and effort. The call blocks
        for every provider round and tool call. Callers run it on a worker
        thread."""
        answer = self.adapter().ask(
            turn.question,
            system=turn.system,
            tools=turn.tools,
            model=self.model,
            effort=self.config["effort"],
            history=turn.history,
            budget=turn.budget,
            on_step=turn.on_step,
            messages=turn.messages,
        )
        if answer.provider is None:
            answer.provider = self.provider
        return answer

    def probe(self) -> None:
        """Raises the provider's own exception on failure."""
        options = self.config.get("options", {})
        if self.provider in ("anthropic", "bedrock"):
            from hst.app.agent.anthropic_ import probe as probe_anthropic

            probe_anthropic(self.provider, self.secrets, options, self.model, self.trust)
        else:
            from hst.app.agent.openrouter import probe as probe_openrouter

            probe_openrouter(self.secrets, options, self.model, self.trust)
