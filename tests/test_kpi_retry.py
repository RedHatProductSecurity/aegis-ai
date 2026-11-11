"""Behavioral regressions for retry policies on reused SDK sessions."""

from types import SimpleNamespace

import pytest
import requests

from aegis_ai_web.src.endpoints import kpi_retry
from tests.kpi_helpers import Clock, RecordingClient, add_list_page


class Session:
    """Minimal SDK boundary with time spent before endpoint dispatch."""

    def __init__(self, clock):
        self._Session__client = RecordingClient()
        self.token_manager = SimpleNamespace(client=self._Session__client)
        self.clock = clock
        self.calls = 0

    def call(self, endpoint, *args, **kwargs):
        self.calls += 1
        self.clock.sleep(0.1)
        return endpoint(*args, client=self._Session__client, **kwargs)


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(kpi_retry, "time", clock)
    return clock


@pytest.mark.parametrize("same_policy", [False, True])
def test_repeated_attach_uses_one_timeout_adapter(clock, same_policy):
    session = Session(clock)
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 20)
    for _ in range(20):
        if not same_policy:
            retry = kpi_retry.OSIDBRetry(clock.monotonic() + 20)
        retry.attach(session)
    result = session.call(lambda *, client: client.timeout)
    assert result == pytest.approx(19.9)
    assert session.calls == 1
    assert session._Session__client.timeouts == pytest.approx([20, 19.9])
    assert session.token_manager.client is session._Session__client


def test_new_requests_ignore_previous_expired_deadlines_and_forward_arguments(clock):
    session = Session(clock)
    seen = []

    def endpoint(value, *, client, offset):
        seen.append((value, offset, client.timeout))
        return value + offset

    for number in range(6):
        kpi_retry.OSIDBRetry(clock.monotonic() + 2).attach(session)
        assert session.call(endpoint, number, offset=3) == number + 3
        clock.sleep(3)
    assert session.calls == 6
    assert seen == [(number, 3, pytest.approx(1.9)) for number in range(6)]


def test_repeated_attach_does_not_multiply_transient_attempts(clock):
    session = Session(clock)
    started = clock.monotonic()
    for _ in range(8):
        kpi_retry.OSIDBRetry(clock.monotonic() + 60).attach(session)
    attempts = []

    def unavailable(*, client):
        attempts.append(client.timeout)
        raise requests.ReadTimeout("unavailable")

    with pytest.raises(kpi_retry.KPIFailure) as failure:
        session.call(unavailable)
    assert failure.value.status_code == 503
    assert failure.value.metadata == {"retry_exhausted": True}
    assert session.calls == len(attempts) == 4
    assert all(0 < timeout <= 60 for timeout in attempts)
    assert attempts == sorted(attempts, reverse=True)
    # Four SDK calls plus the unchanged 0.25, 0.5, 1.0 second backoffs.
    assert clock.monotonic() - started == pytest.approx(0.4 + 1.75)


@pytest.mark.parametrize(
    "error",
    [requests.ConnectionError("offline"), requests.ReadTimeout("slow")],
)
def test_reattached_policy_recovers_from_transient_failure(clock, error):
    session = Session(clock)
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 20)
    retry.attach(session)
    retry.attach(session)

    def endpoint(*, client):
        if session.calls == 1:
            raise error
        return "recovered"

    assert session.call(endpoint) == "recovered"
    assert session.calls == 2
    assert retry.attempts == {}


def test_reattached_policy_propagates_nontransient_failure(clock):
    session = Session(clock)
    for _ in range(3):
        kpi_retry.OSIDBRetry(clock.monotonic() + 20).attach(session)
    error = requests.exceptions.SSLError("invalid certificate")

    def endpoint(*, client):
        raise error

    with pytest.raises(requests.exceptions.SSLError) as failure:
        session.call(endpoint)
    assert failure.value is error
    assert session.calls == 1


@pytest.mark.parametrize("status, attempts", [(503, 4), (429, 1), (500, 1)])
def test_reattached_policy_preserves_http_status_policy(clock, status, attempts):
    session = Session(clock)
    for _ in range(3):
        kpi_retry.OSIDBRetry(clock.monotonic() + 20).attach(session)
    response = requests.Response()
    response.status_code = status
    error = requests.HTTPError(response=response)

    def endpoint(*, client):
        raise error

    expected = kpi_retry.KPIFailure if status == 503 else requests.HTTPError
    with pytest.raises(expected):
        session.call(endpoint)
    assert session.calls == attempts


def test_reattaching_same_expired_policy_still_enforces_its_deadline(clock):
    session = Session(clock)
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 1)
    retry.attach(session)
    clock.sleep(2)
    retry.attach(session)
    with pytest.raises(kpi_retry.BudgetDeferred):
        session.call(lambda *, client: "must not run")
    assert session.calls == 0
    assert session._Session__client.timeouts == []


def test_legacy_session_adapter_has_stable_http_client():
    from unittest.mock import MagicMock

    session = MagicMock()
    session.flaws.retrieve_list_iterator.side_effect = lambda **kwargs: iter(())
    add_list_page(session)
    client = session._Session__client
    for _ in range(1000):
        assert client.with_timeout(1) is client
    assert session._Session__client is client
    assert session.mock_calls == []


def test_record_delegates_to_bound_save_with_new_protocol(clock):
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 60)
    saved = []
    retry.bind({}, lambda key, failures: saved.append((key, failures)))

    retry.record("operation", 2)
    retry.record("operation", 0)
    retry.record(None, 1)

    assert saved == [("operation", 2), ("operation", 0)]
    assert retry.attempts == {}


def test_keyless_calls_keep_a_local_four_attempt_bound(clock):
    """Without a retry key nothing is recorded or saved, so the loop keeps
    its own local count and stops after the usual four attempts."""
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 60)
    saved = []
    retry.bind({}, lambda key, failures: saved.append((key, failures)))
    attempts = []

    def endpoint():
        attempts.append(1)
        raise requests.ConnectionError("offline")

    with pytest.raises(kpi_retry.KPIFailure):
        retry.call(endpoint)
    assert len(attempts) == 4
    assert saved == []
    assert retry.attempts == {}


def test_shared_failure_count_stops_the_retry_loop_early(clock):
    """A merge-style save mirrors the persisted count (including failures
    other requests recorded) into the bound attempts dict, and the loop
    never retries below that merged count."""
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 60)
    persisted = {}
    attempts = []

    def merge(key, failures):
        if failures:
            # This request's failure plus three recorded by concurrent
            # requests sharing the same persisted allowance.
            persisted[key] = persisted.get(key, 0) + 1 + 3
            retry.attempts[key] = persisted[key]
        else:
            persisted.pop(key, None)
            retry.attempts.pop(key, None)

    retry.bind(retry.attempts, merge)

    def endpoint():
        attempts.append(1)
        raise requests.ReadTimeout("unavailable")

    with pytest.raises(kpi_retry.KPIFailure) as failure:
        retry.call(endpoint, retry_key="operation")
    assert failure.value.metadata == {"retry_exhausted": True}
    # The very first failure already merged the allowance to its cap, so
    # the loop must not make a second attempt.
    assert len(attempts) == 1
    assert retry.attempts == {"operation": 4}


def test_merged_count_from_a_later_writer_stops_in_flight_loops(clock):
    """A loop already past its attempt sees the merged count at the next
    failure and exits immediately instead of running its remaining tries."""
    retry = kpi_retry.OSIDBRetry(clock.monotonic() + 60)
    attempts = []

    def merge(key, failures):
        if failures:
            retry.attempts[key] = retry.attempts.get(key, 0) + 1
            if len(attempts) == 2:
                # A concurrent request exhausts the shared allowance while
                # this loop has its second attempt in flight.
                retry.attempts[key] = 4

    retry.bind(retry.attempts, merge)

    def endpoint():
        attempts.append(1)
        raise requests.ReadTimeout("unavailable")

    with pytest.raises(kpi_retry.KPIFailure):
        retry.call(endpoint, retry_key="operation")
    assert len(attempts) == 2
    assert retry.attempts == {"operation": 4}
