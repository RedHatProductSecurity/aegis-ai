"""Delivery contract tests using real bindings, HTTP errors, and file locks.

Only the OSIDB HTTP transport and request credentials are replaced. Assertions
describe client-observable results, not the representation of delivery files.
"""

import copy
import json
import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from fastapi.testclient import TestClient

from aegis_ai_web.src import main
from aegis_ai_web.src.endpoints import bot_kpi, kpi_delivery, kpi_retry

URL = "/api/v1/analysis/kpi/osidb-bot"
WATERMARK = "2026-06-01T00:00:00+00:00"


class Clock:
    def __init__(self):
        self.now = 10_000.0
        self.delays = []

    def time(self):
        return self.now

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        self.delays.append(delay)
        self.now += delay


def record(value="LOW", **overrides):
    result = {
        "type": "AI-Bot",
        "value": value,
        "timestamp": "2026-05-01T12:00:00+00:00",
        "data_quality": 0.8,
        "confidence": 0.6,
        "aegis_version": "v1",
    }
    return result | overrides


def flaw(number, **overrides):
    return {
        "cve_id": f"CVE-2026-{number:04d}",
        "updated_dt": WATERMARK,
        "components": ["kernel"],
        "impact": "LOW",
        "cvss_scores": [],
        "aegis_meta": {"processed": True, "impact": [record()]},
    } | overrides


def http_response(status, payload):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode()
    response.url = "https://osidb.example.com/osidb/api/v2/flaws"
    return response


class OSIDBTransport:
    def __init__(self):
        self.flaws = [flaw(i) for i in range(1, 4)]
        self.calls = []
        self.hook = lambda call: None

    def get(self, url, **kwargs):
        call = copy.deepcopy(kwargs)
        # The generated client serializes list filters as comma-separated HTTP
        # query values; decode them at this transport boundary like OSIDB does.
        for name in ("cve_id", "components", "include_fields"):
            if isinstance(call["params"].get(name), str):
                call["params"][name] = call["params"][name].split(",")
        self.calls.append(call)
        failure = self.hook(call)
        if isinstance(failure, Exception):
            raise failure
        if failure is not None:
            return http_response(failure, {"detail": "private upstream failure"})
        return self.success(call["params"])

    def success(self, params):
        requested = params.get("cve_id")
        rows = (
            self.selected(params)
            if requested is None
            else [row for row in self.flaws if row["cve_id"] in requested]
        )
        offset = params.get("offset", 0)
        size = params.get("limit", 1000)
        page = rows[offset : offset + size]
        fields = params.get("include_fields", [])
        page = [
            {key: value for key, value in row.items() if key in fields} for row in page
        ]
        return http_response(
            200,
            {
                "results": page,
                "count": len(rows),
                "next": "next-page" if offset + size < len(rows) else None,
                "previous": None,
            },
        )

    def selected(self, params):
        rows = self.flaws
        if components := params.get("components"):
            rows = [row for row in rows if set(components) & set(row["components"])]
        for name, lower in (("updated_dt__gte", True), ("updated_dt__lte", False)):
            if bound := params.get(name):
                rows = [
                    row
                    for row in rows
                    if (
                        datetime.fromisoformat(row["updated_dt"])
                        >= datetime.fromisoformat(bound)
                        if lower
                        else datetime.fromisoformat(row["updated_dt"])
                        <= datetime.fromisoformat(bound)
                    )
                ]
        return rows

    def counts(self):
        return Counter(
            "detail" if call["params"].get("cve_id") else "index" for call in self.calls
        )


@pytest.fixture
def api(tmp_path, monkeypatch):
    clock = Clock()
    settings = SimpleNamespace(
        bot_kpi_cache_dir=str(tmp_path),
        osidb_server_url="https://osidb.example.com",
        bot_kpi_max_refresh_seconds=20,
        bot_kpi_index_ttl_seconds=300,
        bot_kpi_run_ttl_seconds=1800,
    )
    for module in (bot_kpi, kpi_delivery, kpi_retry):
        monkeypatch.setattr(module, "time", clock)
    for module in (bot_kpi, kpi_delivery):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
    transport = OSIDBTransport()
    monkeypatch.setattr(requests, "get", transport.get)
    identity = SimpleNamespace(token="alice-access-token", principal=None)

    async def token():
        return identity.token

    monkeypatch.setattr(main, "_get_request_osidb_token", token)
    monkeypatch.setattr(
        main, "get_request_scope", lambda: {"username": identity.principal}
    )
    with TestClient(main.app) as client:
        yield SimpleNamespace(
            client=client,
            upstream=transport,
            clock=clock,
            settings=settings,
            identity=identity,
            directory=tmp_path,
        )


def request(api, previous=None, **options):
    params = {"delivery": True, "detail": True, "limit": 1}
    if previous is not None:
        params.update(
            run_id=previous["delivery"]["run_id"],
            cursor=previous["delivery"]["continue_token"],
        )
    return api.client.get(URL, params=params | options)


def ok(response):
    assert response.status_code == 200, response.text
    return response.json()


def invalid(response, status=409):
    assert response.status_code == status, response.text
    assert response.json()["code"] == (
        "kpi_run_expired" if status == 410 else "kpi_run_invalidated"
    )


def test_initial_zero_and_cumulative_aggregates_count_flaws_not_records(api):
    api.upstream.flaws = [
        flaw(1, aegis_meta={"processed": False}),
        flaw(
            2,
            aegis_meta={
                "processed": True,
                "impact": [record(), record(data_quality=0.4)],
            },
        ),
        flaw(
            3,
            impact="IMPORTANT",
            components=["openssl"],
            aegis_meta={
                "processed": True,
                "impact": [record(data_quality=0.9, confidence=None)],
                "cwe_id": [record("CWE-79")],
            },
        ),
    ]
    initial = ok(request(api))
    assert initial["delivery"]["received_flaws"] == 0
    assert initial["delivery"]["selected_flaws"] == 3
    assert initial["delivery"]["complete"] is False
    assert initial["features"] == {} and initial["entries"] == []
    assert initial["total_flaws_processed"] == 0
    assert api.upstream.counts() == {"index": 1}
    zero = ok(request(api, initial))
    assert zero["delivery"]["received_flaws"] == 1
    assert zero["entries"] == [] and zero["total_flaws_processed"] == 0
    partial = ok(request(api, zero))
    assert partial["delivery"]["received_flaws"] == 2
    assert len(partial["entries"]) == 2
    assert partial["total_flaws_processed"] == 1
    assert partial["features"]["impact"]["suggested"] == 1
    final = ok(request(api, partial))
    assert final["delivery"]["received_flaws"] == 3
    assert final["delivery"]["complete"] is True
    assert not final["delivery"]["continue_token"]
    assert final["total_flaws_processed"] == 2
    assert {entry["cve_id"] for entry in final["entries"]} == {"CVE-2026-0003"}
    assert final["available_components"] == ["kernel", "openssl"]
    impact = final["features"]["impact"]
    assert (impact["suggested"], impact["kept"], impact["modified"]) == (2, 1, 1)
    assert impact["acceptance_rate"] == 50.0
    assert impact["avg_data_quality"] == 0.7
    assert impact["avg_confidence"] == 0.6
    # LOW -> IMPORTANT has deviation 0.6; one kept + one changed => 0.3.
    assert impact["avg_suggestion_deviation"] == 0.3
    assert api.upstream.counts() == {"index": 1, "detail": 3}
    assert ok(request(api, initial)) == zero
    assert ok(request(api, zero)) == partial
    assert ok(request(api, partial)) == final
    assert api.upstream.counts() == {"index": 1, "detail": 3}


@pytest.mark.parametrize("detail", [True, False])
def test_empty_selection_is_complete_and_replayable(api, detail):
    api.upstream.flaws = []
    initial = ok(request(api, detail=detail))
    assert initial["delivery"]["complete"] is True
    assert (
        initial["delivery"]["received_flaws"]
        == initial["delivery"]["selected_flaws"]
        == 0
    )
    assert not initial["delivery"]["continue_token"]
    assert (
        ok(request(api, run_id=initial["delivery"]["run_id"], detail=detail)) == initial
    )
    assert api.upstream.counts() == {"index": 1}


def test_warm_cache_new_run_still_starts_at_zero_without_osidb_requests(api):
    initial = ok(request(api, limit=3))
    final = ok(request(api, initial, limit=3))
    assert final["delivery"]["complete"] is True
    api.upstream.calls.clear()
    warm = ok(request(api, limit=3))
    assert warm["delivery"]["run_id"] != initial["delivery"]["run_id"]
    assert warm["delivery"]["received_flaws"] == 0 and warm["features"] == {}
    delivered = ok(request(api, warm, limit=3))
    assert delivered["features"] == final["features"]
    assert delivered["entries"] == final["entries"]
    assert api.upstream.calls == []


def test_selection_ttl_refreshes_new_runs_but_not_existing_membership(api):
    initial = ok(request(api))
    api.upstream.flaws.append(flaw(4))
    api.clock.now += 299
    cached = ok(request(api))
    assert cached["delivery"]["selected_flaws"] == 3
    api.clock.now += 1
    refreshed = ok(request(api))
    assert refreshed["delivery"]["selected_flaws"] == 4
    old = ok(request(api, initial))
    assert old["delivery"]["selected_flaws"] == 3
    assert api.upstream.counts()["index"] == 2


def test_run_observations_and_old_page_replay_survive_another_runs_cache_updates(api):
    initial = ok(request(api))
    first = ok(request(api, initial))
    api.clock.now += 300
    api.upstream.flaws[0]["updated_dt"] = "2026-06-02T00:00:00+00:00"
    api.upstream.flaws[0]["impact"] = "CRITICAL"
    other = ok(request(api))
    changed = ok(request(api, other))
    assert changed["features"]["impact"]["modified"] == 1
    second = ok(request(api, first))
    assert second["features"]["impact"]["kept"] == 2
    assert ok(request(api, initial)) == first


@pytest.mark.parametrize(
    "options",
    [
        {"component": "kernel"},
        {"changed_after": "2026-04-01T00:00:00Z"},
        {"changed_before": "2026-07-01T00:00:00Z"},
        {"recorded_after": "2026-04-01T00:00:00Z"},
        {"recorded_before": "2026-07-01T00:00:00Z"},
        {"aegis_version": "v1"},
        {"detail": False},
        {"limit": 2},
    ],
)
def test_continuations_reject_changed_filters_without_poisoning_original_run(
    api, options
):
    initial = ok(request(api))
    invalid(request(api, initial, **options))
    assert api.upstream.counts() == {"index": 1}
    assert ok(request(api, initial))["delivery"]["received_flaws"] == 1


def test_equivalent_date_and_version_filters_share_identity(api):
    options = {
        "recorded_after": "2026-05-01T12:00:00Z",
        "aegis_version": ["v2", "v1", "v1"],
    }
    initial = ok(request(api, **options))
    equivalent = {
        "recorded_after": "2026-05-01T14:00:00+02:00",
        "aegis_version": ["v1", "v2"],
    }
    assert ok(request(api, initial, **equivalent))["total_flaws_processed"] == 1
    ok(request(api, **equivalent))
    assert api.upstream.counts()["index"] == 1


def test_authorization_and_server_boundaries_do_not_reuse_other_scopes(api):
    alice = ok(request(api))
    ok(request(api, alice))
    api.identity.token = "bob-access-token"
    invalid(request(api, alice))
    bob = ok(request(api))
    ok(request(api, bob))
    assert api.upstream.counts() == {"index": 2, "detail": 2}
    api.settings.osidb_server_url = "https://other-osidb.example.com"
    invalid(request(api, bob))
    ok(request(api))
    assert api.upstream.counts()["index"] == 3
    for path in api.directory.rglob("*.json"):
        assert "alice-access-token" not in path.read_text()
        assert "bob-access-token" not in path.read_text()


def test_rotated_token_cannot_continue_but_original_scope_is_intact(api):
    # This documents the current explicit token-scoping constraint, not a claim
    # that access-token rotation preserves the stable user identity requirement.
    initial = ok(request(api))
    api.identity.token = "alice-refreshed-token"
    invalid(request(api, initial))
    api.identity.token = "alice-access-token"
    assert ok(request(api, initial))["delivery"]["received_flaws"] == 1


def test_selection_and_record_filters_have_distinct_observable_effects(api):
    api.upstream.flaws[1]["components"] = ["openssl"]
    api.upstream.flaws[2]["aegis_meta"]["impact"][0]["aegis_version"] = "v2"
    options = {"component": "kernel", "aegis_version": "v1", "limit": 2}
    initial = ok(request(api, **options))
    final = ok(request(api, initial, **options))
    assert (
        final["delivery"]["selected_flaws"] == final["delivery"]["received_flaws"] == 2
    )
    assert final["total_flaws_processed"] == 1
    assert [entry["cve_id"] for entry in final["entries"]] == ["CVE-2026-0001"]
    assert final["features"]["impact"]["suggested"] == 1


@pytest.mark.parametrize(
    "options", [{"run_id": "../escape"}, {"run_id": "a" * 32}, {"cursor": "foreign"}]
)
def test_invalid_initial_identity_does_not_call_osidb(api, options):
    invalid(request(api, **options))
    assert api.upstream.calls == []


def test_cursor_cannot_be_transferred_between_runs_and_unknown_cursor_does_not_advance(
    api,
):
    first, second = ok(request(api)), ok(request(api))
    invalid(request(api, first, cursor=second["delivery"]["continue_token"]))
    invalid(request(api, first, cursor="unknown"))
    assert ok(request(api, first))["delivery"]["received_flaws"] == 1


@pytest.mark.parametrize("corruption", ["missing", "watermark"])
def test_detail_mismatch_invalidates_terminal_run_and_forces_fresh_selection(
    api, corruption
):
    initial = ok(request(api))
    partial = ok(request(api, initial))
    if corruption == "missing":
        api.upstream.flaws.pop(1)
    else:
        api.upstream.flaws[1]["updated_dt"] = "2026-06-02T00:00:00+00:00"
    invalid(request(api, partial))
    count = len(api.upstream.calls)
    invalid(request(api, partial))
    assert len(api.upstream.calls) == count
    refreshed = ok(request(api))
    assert refreshed["delivery"]["run_id"] != initial["delivery"]["run_id"]
    assert api.upstream.counts()["index"] == 2


def test_run_expires_at_exact_ttl_without_upstream_fetch(api):
    initial = ok(request(api))
    api.clock.now += 1799
    assert ok(request(api, run_id=initial["delivery"]["run_id"])) == initial
    api.clock.now += 1
    invalid(request(api, initial), 410)
    invalid(request(api, run_id=initial["delivery"]["run_id"]), 410)
    assert api.upstream.counts() == {"index": 1}
    assert ok(request(api))["delivery"]["received_flaws"] == 0


def test_concurrent_same_cursor_is_one_page_and_one_upstream_operation(api):
    initial = ok(request(api))
    start = Barrier(3)
    entered, release = Event(), Event()

    def block_detail(call):
        if call["params"].get("cve_id"):
            entered.set()
            assert release.wait(5), "test did not release upstream"

    def fetch():
        start.wait(timeout=5)
        return request(api, initial)

    api.upstream.hook = block_detail
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fetch) for _ in range(2)]
        start.wait(timeout=5)
        try:
            assert entered.wait(5), "detail operation never started"
        finally:
            release.set()
        pages = [ok(future.result(timeout=5)) for future in futures]
    assert pages[0] == pages[1]
    assert pages[0]["delivery"]["received_flaws"] == 1
    assert api.upstream.counts() == {"index": 1, "detail": 1}


@pytest.mark.parametrize("stage", ["index", "detail"])
def test_http_503_recovers_on_fourth_operation_attempt(api, stage):
    attempts = Counter()

    def fail_three(call):
        kind = "detail" if call["params"].get("cve_id") else "index"
        attempts[kind] += 1
        return 503 if kind == stage and attempts[kind] <= 3 else None

    api.upstream.hook = fail_three
    initial = ok(request(api))
    final = ok(request(api, initial))
    assert final["delivery"]["received_flaws"] == 1
    assert attempts[stage] == 4
    assert api.clock.delays == [0.25, 0.5, 1.0]
    calls = [
        call
        for call in api.upstream.calls
        if bool(call["params"].get("cve_id")) == (stage == "detail")
    ]
    assert [call["timeout"] for call in calls] == [20, 19.75, 19.25, 18.25]


def test_exhausted_continuation_lost_response_does_not_multiply_attempts(api):
    initial = ok(request(api))
    partial = ok(request(api, initial))
    api.upstream.hook = lambda _: 503
    failed = request(api, partial)
    assert failed.status_code == 503
    assert failed.json()["retry_exhausted"] is True
    assert failed.json()["run_id"] == initial["delivery"]["run_id"]
    count = len(api.upstream.calls)
    assert api.upstream.counts() == {"index": 1, "detail": 5}
    # Simulate loss of the first error response and retry with a fresh client.
    with TestClient(main.app) as replica:
        params = {
            "delivery": True,
            "detail": True,
            "limit": 1,
            "run_id": initial["delivery"]["run_id"],
            "cursor": partial["delivery"]["continue_token"],
        }
        replay = replica.get(URL, params=params)
    assert replay.status_code == 503 and replay.json()["retry_exhausted"] is True
    assert len(api.upstream.calls) == count
    assert ok(request(api, initial)) == partial
    assert partial["features"]["impact"]["kept"] == 1


def test_successful_batch_survives_later_exhaustion_and_explicit_refresh(api):
    api.upstream.flaws = [flaw(i) for i in range(1, 102)]
    initial = ok(request(api, limit=101))
    failed_ids = ["CVE-2026-0101"]
    api.upstream.hook = lambda call: (
        503 if call["params"].get("cve_id") == failed_ids else None
    )
    failed = request(api, initial, limit=101)
    assert failed.status_code == 503 and failed.json()["retry_exhausted"] is True
    assert api.upstream.counts() == {"index": 1, "detail": 5}
    api.upstream.calls.clear()
    api.upstream.hook = lambda _: None
    refreshed = ok(request(api, limit=101))
    final = ok(request(api, refreshed, limit=101))
    assert final["delivery"]["received_flaws"] == final["total_flaws_processed"] == 101
    assert final["features"]["impact"]["kept"] == 101
    assert api.upstream.counts() == {"detail": 1}
    assert api.upstream.calls[0]["params"]["cve_id"] == failed_ids


def test_pre_run_exhaustion_cooldown_is_scoped_and_expires_at_thirty_seconds(api):
    api.upstream.hook = lambda _: 503
    failed = request(api)
    assert failed.status_code == 503 and failed.json()["retry_exhausted"] is True
    exhausted_at = api.clock.now
    assert api.upstream.counts() == {"index": 4}
    assert request(api).status_code == 503
    assert api.upstream.counts() == {"index": 4}
    api.identity.token = "bob-access-token"
    api.upstream.hook = lambda _: None
    ok(request(api))
    api.identity.token = "alice-access-token"
    api.clock.now = exhausted_at + 29.999
    cooling = request(api)
    assert cooling.status_code == 503, cooling.text
    assert cooling.json()["retry_exhausted"] is True
    api.clock.now = exhausted_at + 30
    ok(request(api))
    assert api.upstream.counts() == {"index": 6}


def test_slow_pre_run_exhaustion_cannot_repeat_four_attempts_after_lost_response(api):
    def slow_unavailable(_):
        api.clock.now += 10
        return 503

    api.upstream.hook = slow_unavailable
    failed = request(api, max_refresh_secs=60)
    assert failed.status_code == 503 and failed.json()["retry_exhausted"] is True
    assert api.upstream.counts() == {"index": 4}
    replay = request(api, max_refresh_secs=60)
    assert replay.status_code == 503 and replay.json()["retry_exhausted"] is True
    assert api.upstream.counts() == {"index": 4}


@pytest.mark.parametrize(
    "failure,status",
    [
        (400, 502),
        (401, 502),
        (403, 502),
        (404, 502),
        (429, 502),
        (500, 502),
        (504, 502),
        (requests.Timeout("timeout"), 503),
        (requests.exceptions.SSLError("certificate verification failed"), 502),
        (requests.exceptions.InvalidURL("invalid URL"), 502),
        (OSError("filesystem failure"), 500),
    ],
)
def test_non503_failures_are_never_retried_or_marked_exhausted(api, failure, status):
    api.upstream.hook = lambda _: failure
    response = request(api)
    assert response.status_code == status, response.text
    assert "retry_exhausted" not in response.json()
    assert "private upstream failure" not in response.text
    assert api.upstream.counts() == {"index": 1}
    assert api.clock.delays == []


def test_deadline_defers_retries_and_fresh_budgets_cannot_reset_attempt_count(api):
    initial = ok(request(api))
    api.upstream.hook = lambda _: 503
    deferred = ok(request(api, initial, max_refresh_secs=1))
    assert deferred["delivery"]["deferred"] is True
    assert deferred["entries"] == [] and deferred["delivery"]["received_flaws"] == 0
    assert (
        deferred["delivery"]["continue_token"] == initial["delivery"]["continue_token"]
    )
    assert (
        deferred["delivery"]["page_id"]
        == initial["delivery"]["continue_token"] + ":deferred"
    )
    assert "retry_exhausted" not in deferred
    assert api.upstream.counts() == {"index": 1, "detail": 3}
    failed = request(api, initial, max_refresh_secs=20)
    assert failed.status_code == 503 and failed.json()["retry_exhausted"] is True
    assert request(api, initial).json()["retry_exhausted"] is True
    assert api.upstream.counts()["detail"] == 4


def test_transient_connection_failure_recovers_without_restarting_population(api):
    initial = ok(request(api))
    partial = ok(request(api, initial))
    attempts = 0

    def fail_once(_):
        nonlocal attempts
        attempts += 1
        return requests.ConnectionError("lost connection") if attempts == 1 else None

    api.upstream.hook = fail_once
    recovered = ok(request(api, partial))
    assert recovered["delivery"]["run_id"] == initial["delivery"]["run_id"]
    assert recovered["delivery"]["received_flaws"] == 2
    assert recovered["features"]["impact"]["kept"] == 2
    assert [entry["cve_id"] for entry in recovered["entries"]] == ["CVE-2026-0002"]
    assert api.upstream.counts() == {"index": 1, "detail": 3}


def test_budget_between_batches_delivers_prefix_instead_of_losing_progress(api):
    api.upstream.flaws = [flaw(i) for i in range(1, 102)]
    initial = ok(request(api, limit=101))

    def consume_budget(call):
        if call["params"].get("cve_id"):
            api.clock.now += 20

    api.upstream.hook = consume_budget
    partial = ok(request(api, initial, limit=101))
    assert partial["delivery"]["received_flaws"] == 100
    assert partial["delivery"]["complete"] is False
    assert partial["features"]["impact"]["kept"] == 100
    api.upstream.hook = lambda _: None
    final = ok(request(api, partial, limit=101))
    assert final["delivery"]["complete"] is True
    assert len(final["entries"]) == 1
    assert final["features"]["impact"]["kept"] == 101


def test_retry_policy_must_not_start_an_operation_after_deadline(api):
    operation = Mock()
    with pytest.raises(kpi_retry.BudgetDeferred):
        kpi_retry.OSIDBRetry(api.clock.monotonic()).call(operation)
    operation.assert_not_called()


def test_delivery_without_detail_keeps_cumulative_metrics_but_omits_records(api):
    initial = ok(request(api, detail=False))
    partial = ok(request(api, initial, detail=False))
    assert partial["delivery"]["received_flaws"] == 1
    assert partial["features"]["impact"]["kept"] == 1
    assert "entries" not in partial and "available_components" not in partial


@pytest.mark.parametrize("corruption", ["duplicate", "missing_watermark"])
def test_inconsistent_selection_is_rejected_and_not_cached(api, corruption):
    if corruption == "duplicate":
        api.upstream.flaws.append(copy.deepcopy(api.upstream.flaws[0]))
    else:
        api.upstream.flaws[0].pop("updated_dt")
    invalid(request(api))
    api.upstream.flaws = [flaw(1)]
    assert ok(request(api))["delivery"]["selected_flaws"] == 1
    assert api.upstream.counts() == {"index": 2}


@pytest.mark.parametrize("corruption", ["duplicate", "missing_watermark"])
def test_inconsistent_details_cannot_silently_be_accepted(api, corruption):
    initial = ok(request(api))
    if corruption == "duplicate":
        api.upstream.flaws.append(copy.deepcopy(api.upstream.flaws[0]))
        api.upstream.flaws[-1]["impact"] = "CRITICAL"
    else:
        api.upstream.flaws[0].pop("updated_dt")
    invalid(request(api, initial))


def test_record_window_inclusive_edges_and_zero_record_flaw_count(api):
    timestamp = "2026-05-01T12:00:00+00:00"
    api.upstream.flaws = [flaw(1), flaw(2)]
    api.upstream.flaws[1]["aegis_meta"]["impact"][0]["timestamp"] = (
        "2026-05-01T12:00:01+00:00"
    )
    options = {"recorded_after": timestamp, "recorded_before": timestamp, "limit": 2}
    initial = ok(request(api, **options))
    final = ok(request(api, initial, **options))
    assert final["delivery"]["received_flaws"] == 2
    assert final["total_flaws_processed"] == 1
    assert final["features"]["impact"]["suggested"] == 1
    assert len(final["entries"]) == 1


def test_changed_date_bounds_restrict_selection_and_do_not_leak_unselected_cache(api):
    initial = ok(request(api, limit=3))
    ok(request(api, initial, limit=3))
    api.upstream.flaws[1]["updated_dt"] = "2026-06-03T00:00:00+00:00"
    options = {
        "changed_after": "2026-06-02T00:00:00Z",
        "changed_before": "2026-06-04T00:00:00Z",
    }
    narrow = ok(request(api, **options))
    final = ok(request(api, narrow, **options))
    assert final["delivery"]["selected_flaws"] == 1
    # The May record is outside the changed-date scoring window even though
    # the flaw was selected by its June updated timestamp.
    assert final["entries"] == [] and final["features"] == {}
    assert final["delivery"]["received_flaws"] == 1


def test_later_osidb_index_http_page_retries_do_not_restart_successful_pages(api):
    api.upstream.flaws = [flaw(i) for i in range(1, 1002)]
    attempts = Counter()

    def fail_later_page(call):
        offset = call["params"].get("offset", 0)
        attempts[offset] += 1
        return 503 if offset == 1000 and attempts[offset] <= 3 else None

    api.upstream.hook = fail_later_page
    initial = ok(request(api))
    assert initial["delivery"]["selected_flaws"] == 1001
    assert attempts == {0: 1, 1000: 4}


def test_concurrent_initial_requests_share_one_selection_query(api):
    start = Barrier(3)

    def fetch():
        start.wait(timeout=5)
        return request(api)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fetch) for _ in range(2)]
        start.wait(timeout=5)
        pages = [ok(future.result(timeout=5)) for future in futures]
    assert pages[0]["delivery"]["run_id"] != pages[1]["delivery"]["run_id"]
    assert api.upstream.counts() == {"index": 1}


def test_concurrent_exhausted_cursor_is_terminal_for_all_waiters(api):
    initial = ok(request(api))
    api.upstream.hook = lambda _: 503
    start = Barrier(3)

    def fetch():
        start.wait(timeout=5)
        return request(api, initial)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fetch) for _ in range(2)]
        start.wait(timeout=5)
        failures = [future.result(timeout=5) for future in futures]
    assert all(response.status_code == 503 for response in failures)
    assert all(response.json()["retry_exhausted"] is True for response in failures)
    assert api.upstream.counts() == {"index": 1, "detail": 4}


def test_no_kerberos_identity_does_not_create_unscoped_cache(api, monkeypatch):
    api.identity.token = None
    monkeypatch.setattr(
        "osidb_bindings.token_cache.resolve_kerberos_principal", lambda: None
    )
    response = request(api)
    assert response.status_code == 503
    assert "retry_exhausted" not in response.json()
    assert api.upstream.calls == []
    assert list(api.directory.rglob("*.json")) == []


@pytest.mark.parametrize("failures", [3, 4])
def test_kerberos_bindings_real_session_call_retries_each_http_operation(
    api, monkeypatch, failures
):
    from osidb_bindings.auth import TokenManager
    from osidb_bindings.session import Session

    api.identity.token = None
    monkeypatch.setattr(
        "osidb_bindings.token_cache.resolve_kerberos_principal",
        lambda: "alice@EXAMPLE.COM",
    )
    monkeypatch.setattr(
        TokenManager,
        "get_access_token",
        lambda self, force_refresh=False: "service-token",
    )
    monkeypatch.setattr(
        bot_kpi.osidb_bindings,
        "new_session",
        lambda osidb_server_uri: Session(
            base_url=osidb_server_uri,
            token_cache_enabled=False,
        ),
    )
    attempts = Counter()

    def fail(call):
        kind = "detail" if call["params"].get("cve_id") else "index"
        attempts[kind] += 1
        return 503 if attempts[kind] <= failures else None

    api.upstream.hook = fail
    initial = request(api)
    if failures == 4:
        assert initial.status_code == 503 and initial.json()["retry_exhausted"] is True
        assert attempts == {"index": 4}
    else:
        final = ok(request(api, ok(initial)))
        assert final["delivery"]["received_flaws"] == 1
        assert attempts == {"index": 4, "detail": 4}


def test_verified_principal_survives_token_rotation_without_requery(api):
    api.identity.principal = "alice@example.com"
    initial = ok(request(api))
    partial = ok(request(api, initial))
    api.identity.token = "alice-refreshed-token"
    assert ok(request(api, initial)) == partial
    assert ok(request(api, partial))["delivery"]["received_flaws"] == 2
    assert api.upstream.counts() == {"index": 1, "detail": 2}
    api.identity.principal = "bob@example.com"
    invalid(request(api, partial))
    assert api.upstream.counts() == {"index": 1, "detail": 2}


def test_verified_principal_cache_shares_details_across_filters_and_page_options(api):
    api.identity.principal = "alice@example.com"
    initial = ok(request(api, limit=3))
    ok(request(api, initial, limit=3))
    api.upstream.calls.clear()
    # Scoring options and page size must not trigger index or detail fetches.
    options = {"limit": 2, "detail": False, "aegis_version": "v1"}
    narrowed = ok(request(api, **options))
    page = ok(request(api, narrowed, **options))
    assert page["features"]["impact"]["kept"] == 2
    assert api.upstream.calls == []
    # A different flaw-selection query needs an index, but reuses flaw details.
    options = {"component": "kernel", "limit": 2}
    filtered = ok(request(api, **options))
    assert ok(request(api, filtered, **options))["features"]["impact"]["kept"] == 2
    assert api.upstream.counts() == {"index": 1}


def test_slow_index_pages_resume_across_requests_with_retimed_calls(api):
    api.upstream.flaws = [flaw(i) for i in range(1, 2002)]

    def slow_index(call):
        if not call["params"].get("cve_id"):
            api.clock.now += 20

    api.upstream.hook = slow_index
    initial = ok(request(api))
    assert initial["entries"] == [] and initial["features"] == {}
    assert initial["delivery"]["continue_token"]
    assert initial["delivery"]["selection_complete"] is False
    assert initial["delivery"]["deferred"] is True
    assert initial["delivery"]["selected_flaws"] == 0
    assert initial["delivery"]["complete"] is False
    pending = ok(request(api, initial))
    assert (
        pending["delivery"]["continue_token"] == initial["delivery"]["continue_token"]
    )
    assert (
        pending["delivery"]["page_id"]
        == initial["delivery"]["continue_token"] + ":deferred"
    )
    assert pending["delivery"]["selection_complete"] is False
    known = ok(request(api, pending))
    assert known["delivery"]["selection_complete"] is True
    assert known["delivery"]["selected_flaws"] == 2001
    assert known["delivery"]["received_flaws"] == 0
    assert known["delivery"]["deferred"] is True
    assert known["delivery"]["continue_token"] == initial["delivery"]["continue_token"]
    accepted = ok(request(api, known))
    assert accepted["delivery"]["received_flaws"] == 1
    assert accepted["delivery"]["page_id"] == initial["delivery"]["continue_token"]
    assert accepted["delivery"]["deferred"] is False
    assert ok(request(api, initial)) == accepted
    indexes = [call for call in api.upstream.calls if not call["params"].get("cve_id")]
    assert [call["params"].get("offset", 0) for call in indexes] == [0, 1000, 2000]
    assert [call["timeout"] for call in indexes] == [20, 20, 20]


def test_each_index_http_page_uses_remaining_timeout_not_original_budget(api):
    api.upstream.flaws = [flaw(i) for i in range(1, 2002)]

    def consume(call):
        if not call["params"].get("cve_id"):
            api.clock.now += 5

    api.upstream.hook = consume
    initial = ok(request(api))
    assert initial["delivery"]["selection_complete"] is True
    assert [call["timeout"] for call in api.upstream.calls] == [20, 15, 10]


def test_known_selection_detail_budget_deferral_holds_cursor_and_partial_metrics(api):
    initial = ok(request(api))
    partial = ok(request(api, initial))

    def slow_retry(_):
        api.clock.now += 20
        return requests.ReadTimeout("upstream stalled")

    api.upstream.hook = slow_retry
    deferred = ok(request(api, partial))
    assert deferred["delivery"]["deferred"] is True
    assert deferred["delivery"]["selection_complete"] is True
    assert deferred["delivery"]["received_flaws"] == 1
    assert deferred["features"] == partial["features"]
    assert deferred["available_components"] == partial["available_components"]
    assert deferred["entries"] == []
    assert (
        deferred["delivery"]["continue_token"] == partial["delivery"]["continue_token"]
    )
    assert (
        deferred["delivery"]["page_id"]
        == partial["delivery"]["continue_token"] + ":deferred"
    )
    api.upstream.hook = lambda _: None
    recovered = ok(request(api, partial))
    assert recovered["delivery"]["received_flaws"] == 2
    assert recovered["delivery"]["page_id"] == partial["delivery"]["continue_token"]
    assert recovered["features"]["impact"]["kept"] == 2


@pytest.mark.parametrize(
    "failure", [requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout]
)
def test_transient_transport_failures_retry_four_times_with_usable_time(api, failure):
    api.upstream.hook = lambda _: failure("unavailable")
    failed = request(api)
    assert failed.status_code == 503 and failed.json()["retry_exhausted"] is True
    assert api.upstream.counts() == {"index": 4}
    assert [call["timeout"] for call in api.upstream.calls] == [20, 19.75, 19.25, 18.25]


def test_cleanup_removes_expired_runs_across_scopes_but_skips_locked_files(api):
    initial = ok(request(api))
    run_path = next(api.directory.rglob(initial["delivery"]["run_id"] + ".json"))
    # A file currently held by another request must survive the sweep.
    with kpi_delivery.handler(run_path, kpi_delivery.DeliveryRun):
        api.clock.now += 1800
        api.identity.token = "bob-access-token"
        ok(request(api))
        assert run_path.exists()
    api.clock.now += 60
    ok(request(api))
    assert not run_path.exists()
    api.identity.token = "alice-access-token"
    invalid(request(api, initial), 410)


def test_cleanup_preserves_flaw_cache_active_runs_and_unknown_filenames(api):
    initial = ok(request(api))
    ok(request(api, initial))
    run_path = next(api.directory.rglob(initial["delivery"]["run_id"] + ".json"))
    unrelated = run_path.parent / "unrelated.json"
    unrelated.write_text("do not delete")
    cache = run_path.parent / "flaws.json"
    before = cache.read_bytes()
    api.clock.now += 60
    ok(request(api))
    assert run_path.exists() and unrelated.read_text() == "do not delete"
    assert cache.read_bytes() == before


def test_cleanup_does_not_follow_scoped_directory_symlinks(api, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / ("a" * 32 + ".json")
    victim.write_text("{}")
    root = api.directory / "delivery"
    root.mkdir()
    (root / ("b" * 64)).symlink_to(outside, target_is_directory=True)
    ok(request(api))
    assert victim.exists(), "cleanup followed a directory symlink outside KPI storage"
    assert not (outside / ".guard").exists()


@pytest.mark.parametrize("kind", ["run", "selection"])
@pytest.mark.parametrize("dangling", [False, True], ids=["existing", "dangling"])
def test_cleanup_does_not_open_or_remove_symlinked_state_files(
    api, tmp_path, monkeypatch, kind, dangling
):
    initial = ok(request(api))
    run_path = next(api.directory.rglob(initial["delivery"]["run_id"] + ".json"))
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "untouched.json"
    if not dangling:
        target.write_text("{}")
    name = "a" * 32 if kind == "run" else "selection-" + "a" * 64
    link = run_path.parent / (name + ".json")
    link.symlink_to(target)
    original_open = os.open

    def guarded_open(path, *args, **kwargs):
        assert Path(path) not in {link, target, outside / ".guard"}
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    api.clock.now += 60
    ok(request(api))
    assert link.is_symlink()
    assert target.exists() is not dangling
    if not dangling:
        assert target.read_text() == "{}"
    assert not (outside / ".guard").exists()
