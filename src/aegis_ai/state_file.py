"""Generic JSON state file guarded by an advisory lock on the file itself.

A single small primitive shared by callers that need to persist one pydantic
model to disk with concurrency safety.  The state file *is* the lock -- there
is no separate ``.lock`` sidecar, so there is only ever one file whose presence
or absence needs reasoning about.

Two lock disciplines are supported:

* non-blocking (default) -- fail fast if another holder has the lock, suitable
  for a single-instance process that must not run twice against one file;
* blocking -- wait for the lock, suitable for serializing the read-modify-write
  cycles of concurrent requests in a web server.
"""

import fcntl
import json
import logging
import os
from typing import Never, Self

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


class StateFileHandler[T: BaseModel]:
    """Locks a JSON state file and reads/writes a single pydantic model to it.

    Use as a context manager; the lock is held for the lifetime of the ``with``
    block.  ``read()`` returns ``None`` when the file is empty or unparsable,
    so a truncated or corrupt file degrades to "no state" rather than raising.
    """

    def __init__(
        self,
        state_file: str | None,
        model_type: type[T],
        *,
        blocking: bool = False,
        exclude_defaults: bool = False,
    ):
        self.state_file = state_file
        self.model_type = model_type
        self.blocking = blocking
        self.exclude_defaults = exclude_defaults
        self.state_fd = -1

    def _fail(self, e: Exception, msg: str) -> Never:
        logger.debug("%s: %s", msg, e)
        raise RuntimeError(f"{msg}: {self.state_file} ({e.__class__.__name__})")

    def __enter__(self) -> Self:
        if not self.state_file:
            # no state file configured -> no-op handler
            return self

        try:
            self.state_fd = os.open(self.state_file, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as e:
            self._fail(e, "failed to open or create state file")

        flags = fcntl.LOCK_EX if self.blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(self.state_fd, flags)
        except OSError as e:
            os.close(self.state_fd)
            self.state_fd = -1
            self._fail(e, "failed to lock state file")

        logger.debug("locked state file: %s", self.state_file)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self.state_file or self.state_fd < 0:
            return
        fcntl.flock(self.state_fd, fcntl.LOCK_UN)
        os.close(self.state_fd)
        self.state_fd = -1

    def read(self) -> T | None:
        """Read and parse the model from the state file, or None if empty/corrupt."""
        if not self.state_file:
            return None
        assert self.state_fd >= 0
        with os.fdopen(self.state_fd, "r", closefd=False) as f:
            f.seek(0)
            data = f.read()
        if not data:
            return None
        try:
            return self.model_type.model_validate_json(data)
        except (ValidationError, json.JSONDecodeError):
            logger.warning(
                "Failed to load state from %r; treating as no state", self.state_file
            )
            return None

    def write(self, state: T) -> None:
        """Serialize the model and overwrite the state file in place."""
        if not self.state_file:
            return
        assert self.state_fd >= 0
        payload = state.model_dump_json(exclude_defaults=self.exclude_defaults) + "\n"
        raw = payload.encode("utf-8")
        os.lseek(self.state_fd, 0, os.SEEK_SET)
        size = os.write(self.state_fd, raw)
        os.ftruncate(self.state_fd, size)
