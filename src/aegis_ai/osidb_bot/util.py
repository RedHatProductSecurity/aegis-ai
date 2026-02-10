import logging
from typing import Any, MutableMapping


# Flaw data from OSIDB (nested structures; keys/values are often str but not always)
FlawData = dict[str, Any]


class _OsidbBotLogger(logging.LoggerAdapter):
    """Logger that prepends '[osidb-bot] ' to every message."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        return (f"[osidb-bot] {msg}", kwargs)


logger = _OsidbBotLogger(logging.getLogger(__name__), {})
