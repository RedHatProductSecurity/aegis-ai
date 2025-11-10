# check data quality

import logging
from typing import Any

from pydantic_ai import RunContext, Tool, FunctionToolset

from aegis_ai.data_models import CVEID
from aegis_ai.features import cve
from aegis_ai.features.cve.data_models import CVEDataCriticOutput
from aegis_ai.toolsets.tools.osidb import CVE

logger = logging.getLogger(__name__)


class CVEDataCriticToolInput(CVE):
    pass


async def analyse_cve_data(cve_id: CVEID, cve_data: Any) -> CVEDataCriticOutput:
    from aegis_ai.agents.data import default as data_critic_agent

    try:
        cwe_data_critic = cve.CVEDataCritic(agent=data_critic_agent)
        return await cwe_data_critic.exec(
            cve_data.cve_id, static_context=cve_data.model_dump()
        )
    except Exception as e:
        logger.warning(e)
        logger.warning("Unexpected error during CVE data analysis.")
        return CVEDataCriticOutput(
            data_quality=0,
            confidence=0,
            tools_used=[],
            cve_id=cve_id,
            disclaimer=CVEDataCriticOutput.disclaimer,
            explanation="Unexpected error during CVE data analysis.",
        )


@Tool
async def cve_analysis(
    ctx: RunContext, cve_data: CVEDataCriticToolInput
) -> CVEDataCriticOutput:
    """analyze cve data with data_critic agent."""

    return await analyse_cve_data(cve_data.cve_id, cve_data)


toolset = FunctionToolset(
    tools=[cve_analysis],
)

data_critic_toolset = toolset.prefixed("data_critic")
