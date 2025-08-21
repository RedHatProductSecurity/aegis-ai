import logging
import os
import pytest

from pydantic_ai.tools import RunContext, Tool

from aegis_ai import config_logging
from aegis_ai.agents import rh_feature_agent
from aegis_ai.tools.osidb import CVE, CVEID, OsidbDependencies

from evals.utils.osidb_cache import osidb_cache_retrieve


@Tool
async def osidb_tool(ctx: RunContext[OsidbDependencies], cve_id: CVEID) -> CVE:
    """wrapper around aegis.tools.osidb that caches OSIDB responses"""
    return await osidb_cache_retrieve(cve_id)


# enable logging to see progress
@pytest.fixture(scope="session", autouse=True)
def setup_logging_for_session():
    config_logging(level="INFO")

    # suppress noisy INFO messages: AFC is enabled with max remote calls: 10.
    logging.getLogger("google_genai.models").setLevel(logging.WARNING)


# We need to cache OSIDB responses (and maintain them in git) to make
# sure that our evaluation is invariant to future changes in OSIDB data
@pytest.fixture(scope="session", autouse=True)
def override_rh_feature_agent():
    rh_feature_agent._function_toolset.tools["osidb_tool"] = osidb_tool


# Optionally exit successfully if ${AEGIS_EVALS_MIN_PASSED} tests have succeeded
def pytest_sessionfinish(session, exitstatus):
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if not tr:
        return

    min_passed = os.getenv("AEGIS_EVALS_MIN_PASSED")
    if not min_passed:
        return

    # get the actual count of passed tests
    excluded = ["setup", "teardown"]
    passed = sum(1 for t in tr.stats.get("passed") if t.when not in excluded)

    if int(min_passed) <= passed:
        # make pytest exit successfully
        session.exitstatus = pytest.ExitCode.OK
