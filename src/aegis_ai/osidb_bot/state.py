import fcntl
import json
import os

from aegis_ai.osidb_bot.util import logger

from datetime import datetime
from typing import Never, Optional, Self

from pydantic import BaseModel, ValidationError

from aegis_ai.data_models import CVEID


class BotState(BaseModel):
    """State for the OSIDB bot, aligned with osidb_bindings flaw attributes."""

    # the last processed CVE
    last_cve: CVEID

    # creation timestamp of the last processed CVE
    created_dt: datetime

    def __str__(self) -> str:
        return (
            f"BotState(last_cve={self.last_cve!r}, created_dt={str(self.created_dt)!r})"
        )


class StateFileHandler:
    # state file name (path)
    state_file: Optional[str]

    # state file descriptor (OS level)
    state_fd: int

    def __init__(self, state_file: Optional[str]):
        self.state_file = state_file
        self.state_fd = -1

    def _fail(self, e: Exception, msg: str) -> Never:
        logger.debug(f"{msg}: {str(e)}")
        raise RuntimeError(f"{msg}: {self.state_file} ({e.__class__.__name__})")

    def __enter__(self) -> Self:
        if not self.state_file:
            # do nothing
            return self

        # open the state file for reading and writing
        try:
            self.state_fd = os.open(self.state_file, os.O_RDWR | os.O_CREAT)
        except OSError as e:
            self._fail(e, "failed to open or create state file")

        # lock the state file
        try:
            fcntl.flock(self.state_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            self._fail(e, "failed to lock state file")

        logger.debug(f"successfully locked state file: {self.state_file}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self.state_file:
            # do nothing
            return

        # unlock and close the state file
        fcntl.flock(self.state_fd, fcntl.LOCK_UN)
        os.close(self.state_fd)
        self.state_fd = -1

    def read_state(self) -> Optional[BotState]:
        """Read JSON-encoded BotState from state_fd. Returns None if file is empty."""
        if not self.state_file:
            # do nothing
            return

        # read file contents
        assert 0 <= self.state_fd
        with os.fdopen(self.state_fd, "r", closefd=False) as f:
            f.seek(0)
            data = f.read()
        if not data:
            return None

        # parse JSON
        try:
            return BotState.model_validate_json(data)
        except (ValidationError, json.JSONDecodeError):
            logger.warning(
                "Failed to load bot state from %r; treating as no state",
                self.state_file,
            )
            return None

    def write_state(self, state: BotState) -> None:
        """Write JSON-encoded BotState to state_fd."""
        if not self.state_file:
            # do nothing
            return

        assert 0 <= self.state_fd

        # serialize JSON
        payload = state.model_dump_json() + "\n"
        raw = payload.encode("utf-8")

        # write the data at the beginning of the state file
        os.lseek(self.state_fd, 0, os.SEEK_SET)
        size: int = os.write(self.state_fd, raw)
        os.ftruncate(self.state_fd, size)
