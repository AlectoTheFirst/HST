"""Provider descriptors and the stored-settings shape."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from hst.app import egress, tls
from hst.app.ai import prompt

SETTINGS_KEY = "ai"

# The Bedrock adapter puts a region of this form in a host name.
_AWS_REGION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
# The ValueError text of a Bedrock `base_url` that the credentials of the host must not reach.
HOST_CREDENTIALS_DETAIL = (
    "base_url must name a Bedrock Runtime endpoint of the region"
    " when Bedrock uses the credentials of the host"
)

# The prompt layers live in app/ai/prompt.py. This is the drawer prompt of a
# principal offered `query_cypher`, with no site instructions.
DEFAULT_SYSTEM_PROMPT = prompt.DEFAULT_PROMPT


@dataclass
class CredentialField:
    name: str
    label: str
    secret: bool = True
    placeholder: str = ""
    # how the form renders it: "text", "textarea" (PEM material), or
    # "checkbox" (stored as "true" or absent)
    kind: str = "text"
    required: bool = False
    help: str = ""


# The TLS options of one provider. They override the server settings
# TLS_VERIFY and TLS_CA_BUNDLE for that provider (app/tls.py).
TLS_OPTIONS: list[CredentialField] = [
    CredentialField(tls.SKIP_VERIFY, "Skip TLS certificate verification", secret=False, kind="checkbox"),
    CredentialField(
        tls.CA_BUNDLE,
        "CA certificate (PEM, optional)",
        secret=False,
        kind="textarea",
        placeholder="-----BEGIN CERTIFICATE-----",
    ),
]


@dataclass
class ProviderDescriptor:
    id: str
    label: str
    credentials: list[CredentialField]
    models: list[str]
    # the settings form hides the effort field when this is False
    supports_effort: bool = True
    # non-secret settings the provider needs (region, base url, ...)
    options: list[CredentialField] = field(default_factory=list)


PROVIDERS: list[ProviderDescriptor] = [
    ProviderDescriptor(
        id="anthropic",
        label="Anthropic",
        credentials=[
            CredentialField("api_key", "API key", secret=True, placeholder="sk-ant-...", required=True),
        ],
        options=[*TLS_OPTIONS],
        models=["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"],
    ),
    ProviderDescriptor(
        id="bedrock",
        label="AWS Bedrock",
        # `bedrock_auth_mode` picks one of 4 auth modes.
        credentials=[
            CredentialField(
                "aws_bedrock_api_key", "Bedrock API key (optional)", secret=True, placeholder="ABSK..."
            ),
            CredentialField("aws_access_key_id", "Access key id (optional)", secret=True),
            CredentialField("aws_secret_access_key", "Secret access key (optional)", secret=True),
            CredentialField("aws_session_token", "Session token (optional)", secret=True),
        ],
        options=[
            CredentialField(
                "aws_region",
                "AWS region",
                secret=False,
                placeholder="eu-central-1",
                required=True,
                help="Required for every auth mode",
            ),
            CredentialField(
                "aws_role_arn",
                "Role to assume (optional)",
                secret=False,
                placeholder="arn:aws:iam::123456789012:role/hst-bedrock",
            ),
            CredentialField(
                "aws_role_session_name",
                "Role session name (optional)",
                secret=False,
                placeholder="hst",
            ),
            # blank means the SDK's regional default
            CredentialField(
                "base_url",
                "Endpoint URL (optional)",
                secret=False,
                placeholder="https://bedrock-runtime.eu-central-1.amazonaws.com",
                help="Root URL without /anthropic; blank for the Bedrock Runtime endpoint of the region",
            ),
            *TLS_OPTIONS,
        ],
        # Runtime requires inference profiles for these models.
        models=["eu.anthropic.claude-opus-5-5", "global.anthropic.claude-sonnet-5-5"],
    ),
    ProviderDescriptor(
        id="openrouter",
        label="OpenRouter",
        credentials=[
            CredentialField("api_key", "API key", secret=True, placeholder="sk-or-...", required=True),
        ],
        options=[
            CredentialField(
                "base_url",
                "Base URL (optional)",
                secret=False,
                placeholder="https://openrouter.ai/api/v1",
            ),
            *TLS_OPTIONS,
        ],
        models=[
            "anthropic/claude-opus-5",
            "anthropic/claude-sonnet-5",
            "openai/gpt-5",
            "google/gemini-3-pro",
        ],
        supports_effort=False,
    ),
]

BY_ID = {p.id: p for p in PROVIDERS}

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "provider": "anthropic",
    "model": "claude-opus-5",
    "effort": "high",
    "system_prompt": DEFAULT_SYSTEM_PROMPT,
}


def descriptors() -> dict[str, Any]:
    """Payload for GET /api/settings/ai/providers."""
    return {
        "providers": [asdict(p) for p in PROVIDERS],
        # the fixed prompt layers, which the form shows read-only
        "prompt_layers": prompt.fixed_layers(),
    }


def _is_default_prompt(text: str) -> bool:
    """A blank prompt or a verbatim copy of the current default."""
    stripped = text.strip()
    return not stripped or stripped == DEFAULT_SYSTEM_PROMPT.strip()


def merged(stored: dict[str, Any] | None) -> dict[str, Any]:
    """Stored settings over the defaults.

    A stored system prompt that is blank, or a verbatim copy of the current
    default, means "the default".

    `site_instructions` and `prompt_mode` are derived here. A default prompt
    means no site instructions in `append` mode. Any other stored text is the
    site instructions in the stored `prompt_mode`. A row without a
    `prompt_mode` reads as `replace`.
    """
    out = dict(DEFAULTS)
    out.update(stored or {})
    if _is_default_prompt(out.get("system_prompt") or ""):
        out["system_prompt"] = DEFAULT_SYSTEM_PROMPT
        out["site_instructions"] = ""
        out["prompt_mode"] = "append"
    else:
        out["site_instructions"] = out["system_prompt"]
        out["prompt_mode"] = "append" if out.get("prompt_mode") == "append" else "replace"
    return out


def required_credentials(provider: str) -> list[str]:
    """Credential names without which the provider cannot be called.

    "(optional)" in the label marks a field that may be absent.
    """
    p = BY_ID.get(provider)
    if not p:
        return []
    return [c.name for c in p.credentials if "optional" not in c.label.lower()]


def _check_base_url(url: str) -> None:
    """Raise ValueError unless `url` is an https URL with a host and a valid
    port, and without a user part, a backslash, whitespace or a control
    character."""
    if "\\" in url or any(c.isspace() or not c.isprintable() for c in url):
        raise ValueError("base_url must not contain whitespace, a control character or a backslash")
    egress.check_https_url(url, what="base_url")
    parts = urlsplit(url)
    if "@" in parts.netloc:
        raise ValueError("base_url must not contain a user name or a password")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("base_url has an invalid port") from exc


def validate_options(provider: str, options: Mapping[str, str]) -> None:
    """Raise ValueError for a `base_url` or an `aws_region` that the adapter of
    `provider` would put in a URL unchecked, and for a `tls_ca_bundle` that is
    not PEM.

    A blank `aws_region` passes. `bedrock_auth_mode` reports it as missing.
    """
    if provider in ("openrouter", "bedrock") and options.get("base_url"):
        _check_base_url(options["base_url"])
    region = options.get("aws_region") or ""
    if provider == "bedrock" and region.strip() and not _AWS_REGION.fullmatch(region):
        raise ValueError("aws_region must be an AWS region name, for example eu-central-1")
    if options.get(tls.CA_BUNDLE):
        tls.validate_ca_bundle(options[tls.CA_BUNDLE])


def is_bedrock_runtime_host(host: str, region: str) -> bool:
    """Whether `host` is the Bedrock Runtime endpoint of `region`, its FIPS
    endpoint, or a VPC endpoint name of one of the two."""
    service = rf"bedrock-runtime(?:-fips)?\.{re.escape(region)}"
    vpc_endpoint = rf"vpce-[a-z0-9]+(?:-[a-z0-9]+)*\.{service}\.vpce"
    return re.fullmatch(rf"(?:{service}|{vpc_endpoint})\.amazonaws\.com", host) is not None


def uses_host_credentials(secrets: Mapping[str, str], options: Mapping[str, str]) -> bool:
    """Whether Bedrock signs with the credential chain of the host. That is the
    `ambient` mode, and the `assume` mode without a stored access key."""
    mode = bedrock_auth_mode(secrets, options)
    return mode == "ambient" or (mode == "assume" and not secrets.get("aws_access_key_id"))


def validate_endpoint(provider: str, secrets: Mapping[str, str], options: Mapping[str, str]) -> None:
    """Raise ValueError when Bedrock would use the credentials of the host for a
    `base_url` whose host is not a Bedrock Runtime endpoint of `aws_region`."""
    base_url = options.get("base_url")
    if provider != "bedrock" or not base_url or not uses_host_credentials(secrets, options):
        return
    if not is_bedrock_runtime_host(urlsplit(base_url).hostname or "", options["aws_region"]):
        raise ValueError(HOST_CREDENTIALS_DETAIL)


def bedrock_auth_mode(secrets: Mapping[str, str], options: Mapping[str, str]) -> str | None:
    """The Bedrock authentication mode that the stored settings select.

    Checked in this order:

      "api_key"  a Bedrock API key (bearer token), no SigV4
      "assume"   a role ARN, assumed with the credentials the host has
      "keys"     an access key pair, with an optional session token
      "ambient"  no credential entered, the credential chain of the host
                 (instance profile, task role, EC2/EKS metadata or a mounted
                 ~/.aws)

    Returns None when the region is missing.
    """
    if not options.get("aws_region", "").strip():
        return None
    if secrets.get("aws_bedrock_api_key"):
        return "api_key"
    if options.get("aws_role_arn"):
        return "assume"
    if secrets.get("aws_access_key_id") and secrets.get("aws_secret_access_key"):
        return "keys"
    return "ambient"


def is_configured(settings: dict[str, Any], secrets: dict[str, str]) -> bool:
    """Whether the provider has enough to be called.

    For Bedrock, the region is set.
    """
    if settings["provider"] == "bedrock":
        return bedrock_auth_mode(secrets, settings.get("options", {})) is not None
    return all(secrets.get(name) for name in required_credentials(settings["provider"]))
