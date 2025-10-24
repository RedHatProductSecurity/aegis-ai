# check data quality
import logging

from pydantic_ai import RunContext, Tool, FunctionToolset

from aegis_ai.features import cve
from aegis_ai.toolsets.tools.osidb import CVE

logger = logging.getLogger(__name__)


class CVEDataCriticToolInput(CVE):
    pass


@Tool
async def analyse_cve_data(ctx: RunContext, cve_data: CVEDataCriticToolInput):
    """analyze cve data with data_critic agent."""
    from aegis_ai.agents import data_agent

    try:
        cwe_data_critic = cve.CVEDataCritic(agent=data_agent)
        return await cwe_data_critic.exec(
            cve_data.cve_id, static_context=cve_data.model_dump()
        )
    except ValueError:
        return CVEDataCriticToolInput(status="failure", cve_id=cve_data.cve_id)


toolset = FunctionToolset(
    tools=[analyse_cve_data],
)

data_toolset = toolset.prefixed("data_critic")
