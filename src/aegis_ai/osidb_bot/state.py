from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis_ai.data_models import CVEID
from aegis_ai.osidb_bot.util import logger
from aegis_ai.state_file import StateFileHandler as _StateFileHandler


class BotPosition(BaseModel):
    """Position in the CVE stream — hashable, used as dict key in Bot.pending."""

    # make the position hashable so that it can be used as key for a dict
    model_config = ConfigDict(frozen=True)

    # the last processed CVE
    last_cve: CVEID | None = None

    # update timestamp of the last processed CVE
    updated_dt: datetime | None = None


class BotState(BotPosition):
    """Full bot state for persistence — extends BotPosition with mutable fields."""

    model_config = ConfigDict(frozen=False)

    # CVE IDs that failed processing, mapped to remaining retry attempts
    retry_list: dict[str, int] = Field(default_factory=dict)


class StateFileHandler(_StateFileHandler[BotState]):
    """Non-blocking, single-instance lock over the bot's ``BotState`` file.

    Thin specialization of the generic ``aegis_ai.state_file.StateFileHandler``
    that fixes the model to ``BotState`` and keeps the legacy
    ``read_state``/``write_state`` method names used by ``StateProxy``.
    ``exclude_defaults=True`` omits an empty ``retry_list`` from the file.
    """

    def __init__(self, state_file: str | None):
        super().__init__(state_file, BotState, blocking=False, exclude_defaults=True)

    def read_state(self) -> BotState | None:
        return self.read()

    def write_state(self, state: BotState) -> None:
        self.write(state)


class _ObservableDict(dict):
    """Dict subclass that calls a callback when its contents change."""

    _on_change: Any

    def __init__(self, *args: Any, _on_change: Any = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._on_change = _on_change

    def __setitem__(self, key: object, value: object) -> None:
        old = self.get(key)
        super().__setitem__(key, value)
        if old is None:
            logger.info("retry_list: added %s (%s attempts)", key, value)
        elif old != value:
            logger.info("retry_list: updated %s (%s → %s attempts)", key, old, value)
        if self._on_change:
            self._on_change()

    def __delitem__(self, key: object) -> None:
        super().__delitem__(key)
        logger.info("retry_list: removed %s (%d entries remain)", key, len(self))
        if self._on_change:
            self._on_change()

    def pop(self, key: object, *args: Any) -> Any:
        if key not in self:
            return super().pop(key, *args)
        result = super().pop(key, *args)
        logger.info("retry_list: removed %s (%d entries remain)", key, len(self))
        if self._on_change:
            self._on_change()
        return result


class StateProxy:
    """In-memory cache for BotState that auto-writes to disk on update."""

    _sfh: "StateFileHandler"
    _state: BotState
    _retry_list: _ObservableDict
    read_only: bool

    def __init__(self, sfh: "StateFileHandler", read_only: bool = False):
        self._sfh = sfh
        self._state = sfh.read_state() or BotState()
        self._retry_list = _ObservableDict(
            self._state.retry_list, _on_change=self._flush
        )
        self.read_only = read_only
        self._log_position("read")

    @property
    def state(self) -> BotState:
        return self._state

    @property
    def retry_list(self) -> dict[str, int]:
        return self._retry_list

    def _log_position(self, action: str) -> None:
        logger.info(
            "state %s: last_cve=%s, updated_dt=%s, len(retry_list)=%d",
            action,
            self._state.last_cve,
            self._state.updated_dt,
            len(self._retry_list),
        )

    def decrement_retry(self, cve: str) -> None:
        """Decrement the retry count for a CVE, removing it when it reaches zero."""
        if cve not in self._retry_list:
            return

        remains = self._retry_list[cve] - 1
        if remains <= 0:
            self._retry_list.pop(cve)
        else:
            self._retry_list[cve] = remains

    def _flush(self) -> None:
        """Rebuild BotState from current retry_list and write to disk."""
        self._state = BotState(
            last_cve=self._state.last_cve,
            updated_dt=self._state.updated_dt,
            retry_list=self._retry_list,
        )
        if not self.read_only:
            self._sfh.write_state(self._state)

    @state.setter
    def state(self, value: BotPosition) -> None:
        self._state = BotState(
            last_cve=value.last_cve,
            updated_dt=value.updated_dt,
            retry_list=self._retry_list,
        )
        if not self.read_only:
            self._sfh.write_state(self._state)
        self._log_position("written")
