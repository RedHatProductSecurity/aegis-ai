"""File-backed, authorization-scoped KPI delivery runs.

Membership is selected at creation; values are observations made while fetching,
not an atomic historical OSIDB snapshot. Accepted observations never change.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aegis_ai import get_settings
from aegis_ai.state_file import StateFileHandler
from aegis_ai_web.src.data_models import BotKPIDelivery, BotKPIResponse

from . import bot_kpi as kpi
from .kpi_filters import KPIRecordFilters, utc
from .kpi_retry import BudgetDeferred, KPIFailure, OSIDBRetry
from .kpi_state import locked_state, prune_tree

logger = logging.getLogger(__name__)


class Selection(BaseModel):
    created: float = 0
    index: dict[str, str] = Field(default_factory=dict)
    exhausted_until: float = 0
    ready: bool = True
    offset: int = 0
    expected_count: int | None = None
    attempts: dict[str, int] = Field(default_factory=dict)


class Page(BaseModel):
    start: int
    end: int
    continue_token: str | None = None
    selected_flaws: int | None = None
    selection_complete: bool = True
    deferred: bool = False


class DeliveryRun(BaseModel):
    scope: str
    created: float
    index: dict[str, str]
    observations: dict[str, kpi.FlawCacheData] = Field(default_factory=dict)
    pages: dict[str, Page] = Field(default_factory=dict)
    pending: str | None = None
    exhausted: bool = False
    invalidated: bool = False
    selection_pending: bool = False
    attempts: dict[str, int] = Field(default_factory=dict)


def persist(handler: StateFileHandler, state: BaseModel) -> None:
    handler.write(state)
    os.fsync(handler.state_fd)


def handler[T: BaseModel](path: Path, model: type[T]):
    return locked_state(path, model)


def cleanup(directory: Path) -> None:
    prune_tree(
        directory.parent,
        DeliveryRun,
        Selection,
        time.time(),
        get_settings().bot_kpi_run_ttl_seconds,
    )


def scope_key(
    token: str | None, options: dict[str, Any], identity: str | None = None
) -> str:
    # Never write credentials or raw authorization identities to disk/logs.
    authorization = (
        f"principal:{identity}" if identity else (f"token:{token}" if token else None)
    )
    if authorization is None:
        from osidb_bindings.token_cache import resolve_kerberos_principal

        authorization = resolve_kerberos_principal()
        if not authorization:
            raise KPIFailure(503, "Unable to establish the OSIDB authorization scope.")
    encoded = json.dumps(
        [get_settings().osidb_server_url.rstrip("/"), authorization, options],
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


def normalized_options(
    after: datetime | None,
    before: datetime | None,
    component: str | None,
    filters: KPIRecordFilters,
    detail: bool,
    limit: int,
) -> dict[str, Any]:
    def timestamp(value: datetime | None) -> str | None:
        return utc(value).isoformat() if value is not None else None

    return {
        "after": timestamp(after),
        "before": timestamp(before),
        "component": component or None,
        "recorded_after": timestamp(filters.recorded_after),
        "recorded_before": timestamp(filters.recorded_before),
        "versions": sorted(set(filters.aegis_versions)),
        "detail": detail,
        "limit": limit,
    }


def session_for(token: str | None, retry: OSIDBRetry) -> Any:
    session = retry.call(
        kpi._osidb_session,
        get_settings().osidb_server_url,
        token,
        retry.remaining(),
        retry_key="authentication",
    )
    retry.attach(session)
    return session


def selection_path(directory: Path, query: dict[str, Any]) -> Path:
    normalized = {
        key: utc(value).isoformat() if isinstance(value, datetime) else value
        for key, value in query.items()
    }
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    return directory / f"selection-{digest}.json"


def valid_watermark(value: Any) -> bool:
    if not value:
        return False
    try:
        datetime.fromisoformat(str(value))
        return True
    except ValueError:
        return False


def watermark(value: Any) -> str:
    return utc(datetime.fromisoformat(str(value))).isoformat()


def index_page(session: Any, cached: Selection, query: dict[str, Any]) -> None:
    params = kpi._index_query(**query) | {"offset": cached.offset}
    response = session.flaws.retrieve_list(**params).to_dict()
    if not isinstance(response, dict):
        raise TypeError("OSIDB list response must be a mapping")
    rows = response.get("results") or []
    count = response.get("count")
    if cached.expected_count is not None and count != cached.expected_count:
        raise KPIFailure(
            409,
            "OSIDB selection changed. Refresh to restart.",
            code="kpi_run_invalidated",
        )
    for row in rows:
        key, value = row.get("cve_id"), row.get("updated_dt")
        if not key or key in cached.index or not valid_watermark(value):
            raise KPIFailure(
                409,
                "Inconsistent OSIDB selection. Refresh to restart.",
                code="kpi_run_invalidated",
            )
        cached.index[key] = watermark(value)
    cached.expected_count = count
    cached.offset += len(rows)
    cached.ready = not response.get("next")
    if cached.ready and isinstance(count, int) and len(cached.index) != count:
        raise KPIFailure(409, "Incomplete OSIDB selection.", code="kpi_run_invalidated")
    if not rows and not cached.ready:
        raise KPIFailure(
            409, "OSIDB selection made no progress.", code="kpi_run_invalidated"
        )


def refresh_selection(
    state: StateFileHandler,
    cached: Selection,
    token: str | None,
    retry: OSIDBRetry,
    query: dict[str, Any],
) -> Selection:
    started = time.monotonic()
    retry.bind(cached.attempts, lambda key, failures: persist(state, cached))
    try:
        session = session_for(token, retry)
        while not cached.ready:
            retry.remaining()
            index_page(session, cached, query)
            if cached.ready:
                cached.created = time.time()
            persist(state, cached)
    except BudgetDeferred:
        persist(state, cached)
    except KPIFailure as error:
        if error.status_code == 503:
            cached.exhausted_until = time.time() + 30
        else:
            cached = Selection()
        persist(state, cached)
        raise
    finally:
        retry.bind({})
    logger.info(
        "KPI index_seconds=%.3f indexed=%d ready=%s",
        time.monotonic() - started,
        len(cached.index),
        cached.ready,
    )
    return cached


def selection(
    directory: Path, token: str | None, retry: OSIDBRetry, query: dict[str, Any]
) -> Selection:
    with handler(selection_path(directory, query), Selection) as state:
        return load_selection(state, token, retry, query)


def load_selection(
    state: StateFileHandler,
    token: str | None,
    retry: OSIDBRetry,
    query: dict[str, Any],
) -> Selection:
    cached = state.read()
    now = time.time()
    if cached and cached.exhausted_until > now:
        raise KPIFailure(503, "OSIDB is temporarily unavailable.", retry_exhausted=True)
    if cached and cached.exhausted_until:
        cached.attempts = {}
        cached.exhausted_until = 0
    if (
        cached
        and cached.ready
        and now - cached.created < get_settings().bot_kpi_index_ttl_seconds
    ):
        logger.info("KPI selection cache hit selected=%d", len(cached.index))
        return cached
    if (
        cached is None
        or cached.ready
        or now - cached.created >= get_settings().bot_kpi_run_ttl_seconds
    ):
        cached = Selection(
            created=now,
            ready=False,
            attempts=cached.attempts if cached is not None else {},
        )
    logger.info("KPI selection cache miss/resume offset=%d", cached.offset)
    return refresh_selection(state, cached, token, retry, query)


def validate_run(run: DeliveryRun | None, scope: str) -> DeliveryRun:
    if run is None or run.scope != scope:
        raise KPIFailure(
            409,
            "KPI run is unavailable for this request. Refresh to restart.",
            code="kpi_run_invalidated",
        )
    if time.time() - run.created >= get_settings().bot_kpi_run_ttl_seconds:
        raise KPIFailure(
            410, "KPI run expired. Refresh to restart.", code="kpi_run_expired"
        )
    if run.invalidated:
        raise KPIFailure(
            409,
            "KPI selection changed. Refresh to restart.",
            code="kpi_run_invalidated",
        )
    return run


def invalidate(state: StateFileHandler, run: DeliveryRun, directory: Path) -> None:
    run.invalidated = True
    persist(state, run)
    for path in directory.glob("selection-*.json"):
        with handler(path, Selection) as cache:
            persist(cache, Selection())
    logger.info("KPI run invalidated: selected/detail membership inconsistency")
    raise KPIFailure(
        409, "KPI selection changed. Refresh to restart.", code="kpi_run_invalidated"
    )


def accept_batch(
    session: Any,
    ids: list[str],
    run: DeliveryRun,
    state: StateFileHandler,
    directory: Path,
) -> None:
    started = time.monotonic()
    try:
        batch = kpi._fetch_flaws_batch(session, ids, strict=True)
    except KPIFailure as error:
        if error.status_code == 409:
            invalidate(state, run, directory)
        raise
    # Deletion or movement after selection cannot silently become a tombstone.
    if set(batch) != set(ids):
        invalidate(state, run, directory)
    if any(not valid_watermark(batch[key].get("updated_dt")) for key in ids):
        invalidate(state, run, directory)
    observations = {
        cve_id: kpi._flaw_cache_data(batch[cve_id], run.index[cve_id]) for cve_id in ids
    }
    for value in observations.values():
        value.updated_dt = watermark(value.updated_dt)
    if any(value.updated_dt != run.index[key] for key, value in observations.items()):
        invalidate(state, run, directory)
    run.observations.update(observations)
    # Persist each successful batch before attempting another upstream call.
    persist(state, run)
    with handler(directory / "flaws.json", kpi.BotKPICacheEntry) as cache:
        latest = cache.read()
        existing = latest.flaws if latest else {}
        merged = kpi._merge_fetched(existing, observations, {})
        persist(cache, kpi.BotKPICacheEntry(flaws=merged))
    logger.info(
        "KPI detail fetched=%d detail_seconds=%.3f",
        len(ids),
        time.monotonic() - started,
    )


def cached_observations(directory: Path, run: DeliveryRun, ids: list[str]) -> int:
    with handler(directory / "flaws.json", kpi.BotKPICacheEntry) as cache:
        cached = cache.read()
    live = cached.flaws if cached else {}
    hits = 0
    for key in ids:
        value = live.get(key)
        if (
            key not in run.observations
            and value is not None
            and valid_watermark(value.updated_dt)
            and watermark(value.updated_dt) == run.index[key]
            and value.components is not None
        ):
            run.observations[key] = value.model_copy(deep=True)
            hits += 1
    return hits


def refresh_observations(
    token: str | None,
    run: DeliveryRun,
    state: StateFileHandler,
    directory: Path,
    retry: OSIDBRetry,
    stale: list[str],
) -> None:
    session = None
    for offset in range(0, len(stale), kpi._BATCH_SIZE):
        if time.monotonic() >= retry.deadline:
            break
        try:
            if session is None:
                session = session_for(token, retry)
            accept_batch(
                session, stale[offset : offset + kpi._BATCH_SIZE], run, state, directory
            )
        except BudgetDeferred:
            break


def delivered_page(run: DeliveryRun, ids: list[str], start: int) -> Page:
    end = start
    for key in ids:
        if key not in run.observations:
            break
        end += 1
    return Page(
        start=start,
        end=end,
        continue_token=secrets.token_hex(16) if end < len(run.index) else None,
    )


def receive_page(
    token: str | None,
    run: DeliveryRun,
    state: StateFileHandler,
    directory: Path,
    retry: OSIDBRetry,
    limit: int,
) -> Page:
    selected = sorted(run.index)
    start = max((page.end for page in run.pages.values()), default=0)
    ids = selected[start : start + limit]
    hits = cached_observations(directory, run, ids)
    persist(state, run)
    stale = [key for key in ids if key not in run.observations]
    retry.bind(run.attempts, lambda key, failures: persist(state, run))
    refresh_observations(token, run, state, directory, retry, stale)
    page = delivered_page(run, ids, start)
    logger.info(
        "KPI delivery cache_hits=%d cache_misses=%d received=%d selected=%d",
        hits,
        len(stale),
        page.end,
        len(selected),
    )
    return page


def response(
    run: DeliveryRun,
    run_id: str,
    page_id: str,
    page: Page,
    scoring: dict[str, Any],
) -> BotKPIResponse:
    selected = sorted(run.index)
    entry = kpi.BotKPICacheEntry(flaws=run.observations)
    result = entry.to_kpi_result(only_cve_ids=set(selected[: page.end]), **scoring)
    if scoring["detail"]:
        current = entry.to_kpi_result(
            only_cve_ids=set(selected[page.start : page.end]), **scoring
        )
        result.entries = current.entries
    output = kpi._result_to_response(
        result,
        BotKPIDelivery(
            run_id=run_id,
            page_id=page_id,
            continue_token=page.continue_token,
            received_flaws=page.end,
            selected_flaws=page.selected_flaws
            if page.selected_flaws is not None
            else len(selected),
            complete=page.selection_complete
            and page.end
            == (
                page.selected_flaws
                if page.selected_flaws is not None
                else len(selected)
            ),
            selection_complete=page.selection_complete,
            deferred=page.deferred,
        ),
    )
    return output


def create_run(
    directory: Path, scope: str, selected: Selection
) -> tuple[str, DeliveryRun]:
    run_id = f"{int(time.time() * 1000):012x}" + secrets.token_hex(10)
    index = selected.index if selected.ready else {}
    run = DeliveryRun(
        scope=scope,
        created=time.time(),
        index=index,
        selection_pending=not selected.ready,
    )
    first = Page(
        start=0,
        end=0,
        continue_token=secrets.token_hex(16) if index or not selected.ready else None,
        selected_flaws=len(index),
        selection_complete=selected.ready,
        deferred=not selected.ready,
    )
    run.pages[run_id] = first
    run.pending = first.continue_token
    with handler(directory / f"{run_id}.json", DeliveryRun) as state:
        persist(state, run)
    return run_id, run


def advance_run(
    token: str | None,
    run_id: str,
    run: DeliveryRun,
    state: StateFileHandler,
    directory: Path,
    retry: OSIDBRetry,
    limit: int,
) -> Page:
    if run.exhausted:
        raise KPIFailure(
            503,
            "OSIDB retries exhausted. Refresh to restart.",
            retry_exhausted=True,
            run_id=run_id,
        )
    try:
        return receive_page(token, run, state, directory, retry, limit)
    except KPIFailure as error:
        if error.status_code == 503 and error.metadata.get("retry_exhausted"):
            run.exhausted = True
            persist(state, run)
            error.metadata["run_id"] = run_id
        raise


def continue_run(
    directory: Path,
    scope: str,
    run_id: str,
    cursor: str | None,
    token: str | None,
    retry: OSIDBRetry,
    limit: int,
    scoring: dict[str, Any],
    query: dict[str, Any],
) -> BotKPIResponse:
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise KPIFailure(409, "Invalid KPI run identity.", code="kpi_run_invalidated")
    if (
        time.time() - int(run_id[:12], 16) / 1000
        >= get_settings().bot_kpi_run_ttl_seconds
    ):
        raise KPIFailure(
            410, "KPI run expired. Refresh to restart.", code="kpi_run_expired"
        )
    path = directory / f"{run_id}.json"
    if not path.exists():
        raise KPIFailure(
            409,
            "KPI run is unavailable. Refresh to restart.",
            code="kpi_run_invalidated",
        )
    with handler(path, DeliveryRun) as state:
        run = validate_run(state.read(), scope)
        page_id = cursor or run_id
        if page_id in run.pages:
            logger.info("KPI delivery page replay")
            return response(run, run_id, page_id, run.pages[page_id], scoring)
        if cursor != run.pending:
            raise KPIFailure(
                409,
                "Invalid KPI continuation. Refresh to restart.",
                code="kpi_run_invalidated",
            )
        if run.exhausted:
            raise KPIFailure(
                503,
                "OSIDB retries exhausted. Refresh to restart.",
                retry_exhausted=True,
                run_id=run_id,
            )
        if run.selection_pending:
            try:
                selected = selection(directory, token, retry, query)
            except KPIFailure as error:
                if error.status_code == 409:
                    run.invalidated = True
                elif error.metadata.get("retry_exhausted"):
                    run.exhausted = True
                persist(state, run)
                raise
            if not selected.ready:
                page = Page(
                    start=0,
                    end=0,
                    continue_token=cursor,
                    selected_flaws=0,
                    selection_complete=False,
                    deferred=True,
                )
                return response(run, run_id, f"{page_id}:deferred", page, scoring)
            run.index, run.selection_pending = selected.index, False
            persist(state, run)
        page = advance_run(token, run_id, run, state, directory, retry, limit)
        page.selected_flaws = len(run.index)
        if page.end == page.start and page.end < len(run.index):
            page.continue_token, page.deferred = cursor, True
            return response(run, run_id, f"{page_id}:deferred", page, scoring)
        run.pages[page_id] = page
        run.pending = page.continue_token
        persist(state, run)
        return response(run, run_id, page_id, page, scoring)


def get_delivery(
    *,
    osidb_token: str | None,
    run_id: str | None,
    cursor: str | None,
    limit: int,
    deadline: float,
    changed_after: datetime | None,
    changed_before: datetime | None,
    component: str | None,
    record_filters: KPIRecordFilters,
    detail: bool,
    authorization_identity: str | None = None,
) -> BotKPIResponse:
    options = normalized_options(
        changed_after, changed_before, component, record_filters, detail, limit
    )
    scope = scope_key(osidb_token, options, authorization_identity)
    authorization = scope_key(osidb_token, {}, authorization_identity)
    directory = kpi._get_cache_path().parent / "delivery" / authorization
    cleanup(directory)
    retry = OSIDBRetry(deadline)
    query = {
        "changed_after": utc(changed_after) if changed_after is not None else None,
        "changed_before": utc(changed_before) if changed_before is not None else None,
        "component": component,
    }
    scoring = {
        "changed_after": changed_after,
        "changed_before": changed_before,
        "record_filters": record_filters,
        "detail": detail,
    }
    if run_id is None:
        if cursor is not None:
            raise KPIFailure(
                409, "A delivery cursor requires run_id.", code="kpi_run_invalidated"
            )
        selected = selection(directory, osidb_token, retry, query)
        run_id, run = create_run(directory, scope, selected)
        return response(run, run_id, run_id, run.pages[run_id], scoring)
    return continue_run(
        directory, scope, run_id, cursor, osidb_token, retry, limit, scoring, query
    )
