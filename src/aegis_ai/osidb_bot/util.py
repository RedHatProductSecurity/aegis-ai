import logging
from typing import Any, MutableMapping


class _OsidbBotLogger(logging.LoggerAdapter):
    """Logger that prepends '[osidb-bot] ' to every message."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        return (f"[osidb-bot] {msg}", kwargs)


logger = _OsidbBotLogger(logging.getLogger(__name__), {})
