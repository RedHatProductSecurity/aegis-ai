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


# We need to cache OSIDB responses (and maintain them in git) to make
# sure that our evaluation is invariant to future changes in OSIDB data
@pytest.fixture(scope="session", autouse=True)
def override_rh_feature_agent():
    rh_feature_agent._function_toolset.tools["osidb_tool"] = osidb_tool
