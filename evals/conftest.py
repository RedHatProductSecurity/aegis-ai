import logging
import os
import pytest

from pydantic_ai.tools import RunContext, Tool
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai import config_logging
from aegis_ai.tools.osidb import CVE, CVEID, OsidbDependencies
import aegis_ai.toolsets as ts

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
    # Replace the first inner FunctionToolset with one that contains our wrapper
    ts_list = ts.redhat_cve_toolset.toolsets
    if isinstance(ts_list, list):
        ts_list[0] = FunctionToolset(tools=[osidb_tool])


# Optionally exit successfully if ${AEGIS_EVALS_MIN_PASSED} tests have succeeded
def pytest_sessionfinish(session, exitstatus):
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
