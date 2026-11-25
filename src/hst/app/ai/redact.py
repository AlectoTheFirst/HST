"""Remove credentials from provider text before it reaches a log line or an event.

`redact` replaces URL userinfo and query strings, `Authorization`,
`Proxy-Authorization` and `x-api-key` header values, `sk-` style API keys (`sk-ant-`,
`sk-or-`, `sk-proj-`) and AWS access key ids (`AKIA`, `ASIA`) with a marker.
"""

from __future__ import annotations

import re
import traceback

REDACTED = "[redacted]"

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host keeps the scheme and the host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@?#]+@"), rf"\1{REDACTED}@"),
    # the query string of a URL, up to whitespace, a fragment or a closing quote
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s?#'\"<>]*)\?[^\s#'\"<>]*"), rf"\1?{REDACTED}"),
    # a header value in `Name: value`, `'name': 'value'` or `name=value` form
    (
        re.compile(
            r"(?i)\b(authorization|proxy-authorization|x-api-key)(['\"]?\s*[:=]\s*['\"]?)"
            r"(?:(?:bearer|basic)\s+)?[^\s'\",}]+"
        ),
        rf"\1\2{REDACTED}",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{4,}"), REDACTED),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), REDACTED),
)


def redact(text: str) -> str:
    """`text` with every credential that `_RULES` matches replaced by `[redacted]`."""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def redact_exception(exc: BaseException) -> str:
    """The traceback of `exc` with its chained causes, as `traceback` formats
    it, passed through `redact`. A log line holds this text in place of
    `exc_info`. `exc_info` logs the provider text unredacted."""
    return redact("".join(traceback.format_exception(exc)).rstrip())
