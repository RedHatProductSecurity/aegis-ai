"""Request-local retry policy for individual OSIDB operations."""

import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import requests
from fastapi import HTTPException

logger = logging.getLogger(__name__)


class KPIFailure(HTTPException):
    """An endpoint error whose metadata belongs at the JSON top level."""

    def __init__(self, status: int, detail: str, **metadata: Any):
        super().__init__(status, detail)
        self.metadata = metadata


class BudgetDeferred(Exception):
    """No useful HTTP attempt fits; retain progress and continue on another request."""


def transient(error: requests.RequestException) -> bool:
    if isinstance(error, requests.exceptions.SSLError):
        return False
    if isinstance(error, requests.HTTPError):
        return error.response is not None and error.response.status_code == 503
    return isinstance(
        error, (requests.ConnectionError, requests.ReadTimeout, requests.ConnectTimeout)
    )


class OSIDBRetry:
    def __init__(self, deadline: float):
        self.deadline = deadline
        self.minimum_attempt = min(1.0, max((deadline - time.monotonic()) / 4, 0.01))
        self.attempts: dict[str, int] = {}
        self.save: Callable[[str, int], None] | None = None

    def bind(
        self, attempts: dict[str, int], save: Callable[[str, int], None] | None = None
    ) -> None:
        self.attempts, self.save = attempts, save

    def operation_key(self, params: Any) -> str:
        return hashlib.sha256(
            json.dumps(params, sort_keys=True, default=str).encode()
        ).hexdigest()

    def record(self, key: str | None, failures: int) -> None:
        if key is None:
            return
        if failures:
            self.attempts[key] = failures
        else:
            self.attempts.pop(key, None)
        if self.save is not None:
            self.save(key, failures)

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining < self.minimum_attempt:
            raise BudgetDeferred()
        return remaining

    def call(
        self,
        operation: Callable,
        *args: Any,
        retry_key: str | None = None,
        **kwargs: Any,
    ) -> Any:
        first = self.attempts.get(retry_key, 0) if retry_key is not None else 0
        while first < 4:
            self.remaining()
            if first:
                delay = 0.25 * (2 ** (first - 1))
                if self.remaining() - delay < self.minimum_attempt:
                    raise BudgetDeferred()
                logger.info("KPI transient OSIDB retry=%d delay=%.2f", first, delay)
                time.sleep(delay)
            self.remaining()
            try:
                result = operation(*args, **kwargs)
                if first:
                    self.record(retry_key, 0)
                return result
            except requests.RequestException as error:
                if not transient(error):
                    raise
                self.record(retry_key, first + 1)
                if retry_key is None:
                    first += 1
                else:
                    # Requests sharing this allowance may have recorded more
                    # failures meanwhile; never retry below their count.
                    first = max(first + 1, self.attempts.get(retry_key, 0))
        raise KPIFailure(503, "OSIDB is temporarily unavailable.", retry_exhausted=True)

    def attach(self, session: Any) -> None:
        # Session.call is used by each iterator page, including token refresh.
        original = getattr(session, "call", None)
        if not isinstance(original, Callable):
            session.flaws.retry = self
            return
        # A reused session must receive this request's budget, not retain a
        # chain of adapters enforcing expired budgets from earlier requests.
        if isinstance(original, SessionRetryCall):
            original = original.original
        session.call = SessionRetryCall(self, session, original)


class SessionRetryCall:
    """One retry adapter around the SDK call, replaceable between requests."""

    def __init__(self, retry: OSIDBRetry, session: Any, original: Callable):
        self.retry = retry
        self.session = session
        self.original = original

    def __call__(self, endpoint: Callable, *args: Any, **kwargs: Any) -> Any:
        def timed_endpoint(*args: Any, client: Any, **kwargs: Any) -> Any:
            client = client.with_timeout(self.retry.remaining())
            return endpoint(*args, client=client, **kwargs)

        def invoke() -> Any:
            _retimeout_session(self.session, self.retry.remaining())
            return self.original(timed_endpoint, *args, **kwargs)

        key = self.retry.operation_key({"args": args, "kwargs": kwargs})
        return self.retry.call(invoke, retry_key=key)


def _retimeout_session(session: Any, timeout: float) -> None:
    """Re-apply a per-call HTTP timeout to an OSIDB session in place.

    Called at session creation and again before the index query and every
    batch fetch, so OSIDB calls started later in the request are bounded by
    the time actually remaining rather than the original budget. Both
    session kinds are handled: the Kerberos bindings session keeps its HTTP
    client in a private name-mangled attribute, and its token manager
    captured the same client at construction, so both are repointed (the
    token manager's login() derives its SPNEGO client from this one via
    with_auth(), keeping refresh/login behavior unchanged); the bearer
    facade keeps the client on its flaws operations object. Sessions
    exposing neither (e.g. test doubles) keep their current timeout.
    """
    client = getattr(session, "_Session__client", None)
    if client is not None and hasattr(client, "with_timeout"):
        timed_client = client.with_timeout(timeout)
        # The mangled private client is the only way to bound the bindings
        # session's per-call HTTP timeout.
        session._Session__client = timed_client
        token_manager = getattr(session, "token_manager", None)
        if token_manager is not None:
            token_manager.client = timed_client
        return
    flaws = getattr(session, "flaws", None)
    client = getattr(flaws, "_client", None)
    if flaws is not None and client is not None and hasattr(client, "with_timeout"):
        flaws._client = client.with_timeout(timeout)
