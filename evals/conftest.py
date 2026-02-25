import logging
import os

# Set before any aegis_ai import so the main package's flaw_tool uses cache in evals/CI
os.environ.setdefault(
    "OSIDB_CACHE_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "osidb_cache"),
)

import pytest

from pydantic_ai.tools import RunContext, Tool
from pydantic_ai.toolsets import CombinedToolset, FunctionToolset

from aegis_ai import config_logging
from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools.osidb import CVE, cve_exclude_fields, OSIDBToolInput
import aegis_ai.toolsets as ts

from evals.features.common import eval_metrics, eval_summary
from evals.utils.osidb_cache import osidb_cache_retrieve


@Tool
async def osidb_tool(ctx: RunContext[feature_deps], input: OSIDBToolInput) -> CVE:
    """wrapper around aegis.tools.osidb that caches OSIDB responses"""
    cve = await osidb_cache_retrieve(input.cve_id)
    # Features that don't pass deps (e.g. ComponentIntelligence) leave ctx.deps None
    exclude = (
        getattr(ctx.deps, "exclude_osidb_fields", []) if ctx.deps is not None else []
    )
    return cve_exclude_fields(cve, exclude)


# enable logging to see progress
@pytest.fixture(scope="session", autouse=True)
def setup_logging_for_session():
    level = "DEBUG" if logging.getLogger().isEnabledFor(logging.DEBUG) else "INFO"
    config_logging(level=level)

    # Suppress noisy httpx/httpcore request logs during eval runs only
    for noisy_logger in ("httpx", "httpx._client", "httpcore"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    # Suppress ONLY the "[tool call] ... started" logs during eval runs,
    # keep the "... finished" logs visible for timing.
    class _SuppressToolStartedFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            try:
                msg = record.getMessage()
            except Exception:
                return True
            return not (msg.startswith("[tool call] ") and msg.endswith(" started"))

    logging.getLogger("aegis_ai.toolsets").addFilter(_SuppressToolStartedFilter())


# We also replace the toolset so the agent only has our cache-only osidb_tool
# (no component_count_tool / component_flaw_tool that would still hit live OSIDB).
# Apply at import time so the agent sees the cache-only toolset.
def _override_rh_feature_agent_osidb():
    wrapped = ts.redhat_cve_toolset.wrapped
    if isinstance(wrapped, CombinedToolset):
        wrapped.toolsets[0] = FunctionToolset(tools=[osidb_tool])  # type:ignore


_override_rh_feature_agent_osidb()


# Optionally exit successfully if ${AEGIS_EVALS_MIN_PASSED} tests have succeeded
def pytest_sessionfinish(session, exitstatus):
    # print evaluation summary for each feature
    for feat, summary in eval_summary.items():
        logging.info(f"[{feat}] {summary}")

        metrics = eval_metrics[feat]
        if not metrics:
            # the metrics might not be available if all cases failed
            continue

        # print evaluation score for each evaluator and average duration for each feature
        for eval_name, score in metrics.scores.items():
            logging.info(f"[{feat}] {eval_name}: {score:.4f}")

        evaluator_duration = metrics.total_duration - metrics.task_duration
        if metrics.assertions is not None:
            logging.info(f"[{feat}] assertions ratio: {metrics.assertions * 100:.1f}%")
        logging.info(f"[{feat}] average case duration: {metrics.task_duration:.2f}s")
        logging.info(f"[{feat}] average evaluator duration: {evaluator_duration:.2f}s")

    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if not tr:
        return

    min_passed = os.getenv("AEGIS_EVALS_MIN_PASSED")
    if min_passed:
        # get the actual count of passed tests
        passed = tr.stats.get("passed")
        num_passed = 0
        if passed:
            excluded = ["setup", "teardown"]
            num_passed = sum(1 for t in passed if t.when not in excluded)

        if int(min_passed) <= num_passed:
            # make pytest exit successfully
            session.exitstatus = pytest.ExitCode.OK

    logging.info(f"[pytest] exit status: {session.exitstatus}")
