import logging
import os
import pytest

from pydantic_ai.tools import RunContext, Tool
from pydantic_ai.toolsets import CombinedToolset, FunctionToolset

from aegis_ai import config_logging
from aegis_ai.tools.osidb import CVE, OSIDBToolInput
import aegis_ai.toolsets as ts

from evals.features.common import eval_metrics
from evals.utils.osidb_cache import osidb_cache_retrieve


@Tool
async def osidb_tool(ctx: RunContext, input: OSIDBToolInput) -> CVE:
    """wrapper around aegis.tools.osidb that caches OSIDB responses"""
    return await osidb_cache_retrieve(input.cve_id)


# enable logging to see progress
@pytest.fixture(scope="session", autouse=True)
def setup_logging_for_session():
    config_logging(level="INFO")


# We need to cache OSIDB responses (and maintain them in git) to make
# sure that our evaluation is invariant to future changes in OSIDB data
@pytest.fixture(scope="session", autouse=True)
def override_rh_feature_agent():
    # Replace the first inner FunctionToolset with one that contains our wrapper
    wrapped = ts.redhat_cve_toolset.wrapped
    if isinstance(wrapped, CombinedToolset):
        wrapped.toolsets[0] = FunctionToolset(tools=[osidb_tool])  # type:ignore


# Optionally exit successfully if ${AEGIS_EVALS_MIN_PASSED} tests have succeeded
def pytest_sessionfinish(session, exitstatus):
    # print evaluation score for each evaluator and average duration for each feature
    for feat, metrics in eval_metrics.items():
        if not metrics:
            # the metrics might not be available if all cases failed
            continue

        for eval_name, score in metrics.scores.items():
            logging.info(f"[{feat}] {eval_name}: {score:.4f}")

        logging.info(f"[{feat}] assertions ratio: {metrics.assertions * 100:.1f}%")
        logging.info(f"[{feat}] average duration: {metrics.total_duration:.2f}s")

    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if not tr:
        return

    min_passed = os.getenv("AEGIS_EVALS_MIN_PASSED")
    if not min_passed:
        return

    # get the actual count of passed tests
    passed = tr.stats.get("passed")
    num_passed = 0
    if passed:
        excluded = ["setup", "teardown"]
        num_passed = sum(1 for t in passed if t.when not in excluded)

    if int(min_passed) <= num_passed:
        # make pytest exit successfully
        session.exitstatus = pytest.ExitCode.OK
