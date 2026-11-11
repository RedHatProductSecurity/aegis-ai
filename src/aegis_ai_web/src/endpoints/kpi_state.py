"""Lock-safe state acquisition and expiry cleanup for a scoped KPI directory."""

import errno
import fcntl
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel

from aegis_ai.state_file import StateFileHandler


@contextmanager
def directory_guard(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / ".guard", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield descriptor
    finally:
        os.close(descriptor)


def try_open[T: BaseModel](path: Path, model: type[T]) -> StateFileHandler[T] | None:
    state = StateFileHandler(str(path), model)
    try:
        state.__enter__()
        return state
    except RuntimeError as error:
        cause = error.__context__
        if (
            not str(error).startswith("failed to lock state file")
            or not isinstance(cause, OSError)
            or cause.errno not in (errno.EAGAIN, errno.EACCES)
        ):
            raise
        return None


@contextmanager
def locked_state[T: BaseModel](path: Path, model: type[T]):
    # Never wait on a file inode while holding the directory guard. Cleanup can
    # unlink only after it holds that guard AND the file's nonblocking lock.
    while True:
        with directory_guard(path.parent):
            state = try_open(path, model)
        if state is not None:
            break
        time.sleep(0.01)
    try:
        yield state
    finally:
        state.__exit__(None, None, None)


def prune_file(path: Path, model: type[BaseModel], now: float, ttl: int) -> None:
    if path.is_symlink():
        return
    state = try_open(path, model)
    if state is None:
        return
    try:
        value = state.read()
        if value is None or (
            now - getattr(value, "created", now) >= ttl
            and getattr(value, "exhausted_until", 0) <= now
        ):
            path.unlink()
    finally:
        state.__exit__(None, None, None)


def prune(
    directory: Path,
    run_model: type[BaseModel],
    selection_model: type[BaseModel],
    now: float,
    ttl: int,
) -> None:
    with directory_guard(directory) as descriptor:
        previous = os.pread(descriptor, 64, 0)
        if previous and now - float(previous) < min(60, ttl):
            return
        for path in directory.glob("*.json"):
            if re.fullmatch(r"selection-[0-9a-f]{64}", path.stem):
                model = selection_model
            elif re.fullmatch(r"[0-9a-f]{32}", path.stem):
                model = run_model
            else:
                continue
            prune_file(path, model, now, ttl)
        payload = str(now).encode()
        os.pwrite(descriptor, payload, 0)
        os.ftruncate(descriptor, len(payload))


def prune_tree(
    root: Path,
    run_model: type[BaseModel],
    selection_model: type[BaseModel],
    now: float,
    ttl: int,
) -> None:
    with directory_guard(root) as descriptor:
        previous = os.pread(descriptor, 64, 0)
        if previous and now - float(previous) < min(60, ttl):
            return
        for directory in root.iterdir():
            if not directory.is_symlink() and directory.is_dir():
                prune(directory, run_model, selection_model, now, ttl)
        payload = str(now).encode()
        os.pwrite(descriptor, payload, 0)
        os.ftruncate(descriptor, len(payload))
