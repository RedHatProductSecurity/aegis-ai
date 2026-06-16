import logging
from pathlib import Path
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


def log_memory(label: str) -> None:
    """Log process RSS and cgroup memory usage at a named checkpoint."""
    if not logger.isEnabledFor(logging.DEBUG):
        return
    parts = [f"[mem] {label}:"]
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmPeak:", "VmSize:")):
                parts.append(line.strip())
    except (OSError, ValueError):
        pass
    for cg_path in (
        Path("/sys/fs/cgroup/memory.current"),
        Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"),
    ):
        try:
            raw = int(cg_path.read_text().strip())
            parts.append(f"cgroup={raw // (1024 * 1024)}Mi")
            break
        except (OSError, ValueError):
            continue
    logger.debug(" ".join(parts))
