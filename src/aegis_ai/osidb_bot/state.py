import fcntl
import os

from aegis_ai.osidb_bot.util import logger

from typing import Never, Optional, Self


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
