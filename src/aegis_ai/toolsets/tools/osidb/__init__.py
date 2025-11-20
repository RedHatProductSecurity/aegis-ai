import logging
import os

from typing import List, Any, Optional

from pydantic import Field

from pydantic_ai import (
    RunContext,
    Tool,
)
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools import BaseToolOutput, BaseToolInput
from aegis_ai.toolsets.tools.osidb.osidb_client import OSIDBClient

logger = logging.getLogger(__name__)

OSIDB_RETRIEVE_EMBARGOED = os.getenv(
    "AEGIS_OSIDB_RETRIEVE_EMBARGOED", "false"
).lower() in ("true", "1", "t", "y", "yes")


client = OSIDBClient()


class OSIDBToolInput(BaseToolInput):
    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )


class CVE(BaseToolOutput):
    """ """

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )
    cwe_id: Optional[str] = Field(
        default="",
        description="CVE CWE ID.",
    )
    impact: Optional[str] = Field(
        default="",
        description="CVE impact.",
    )
    title: str = Field(
        ...,
        description="CVE title.",
    )
    statement: str = Field(
        ...,
        description="CVE statement.",
    )
    comment_zero: str = Field(..., description="CVE comment_zero.")
    comments: str = Field(
        ...,
        description="all public comments.",
    )
    description: str = Field(..., description="CVE cve_description.")
    components: List = Field(..., description="list of components")
    references: List = Field(..., description="list of references")
    affects: List = Field(..., description="list of affects")
    cvss_scores: List = Field(..., description="list of cvss scores")


async def cve_retrieve(cve_id: CVEID, exclude_fields: List[str] = []) -> CVE:
    logger.info(f"retrieving {cve_id} from osidb")
    validated_cve_id = cveid_validator.validate_python(cve_id)

    try:
        # Retrieval of embargoed flaws is disabled by default, to enable set env var `AEGIS_OSIDB_RETRIEVE_EMBARGOED`
        flaw = await client.get_flaw_data(validated_cve_id, OSIDB_RETRIEVE_EMBARGOED)

        # This logic is about default constraining LLM access to embargo information ... for additional programmatic safety, user acl always
        # dictates if a user has access or not.
        if not OSIDB_RETRIEVE_EMBARGOED and flaw.embargoed:
            logger.info(
                f"retrieved {validated_cve_id} from osidb but it is under embargo and AEGIS_OSIDB_RETRIEVE_EMBARGOED is set 'false'."
            )
            raise ValueError(f"Could not retrieve {cve_id}")

        logger.info(f"{validated_cve_id}:{flaw.title}")
        comments = ""
        for i, comment in enumerate(flaw.comments):
            if i >= 15:  # FIXME: remove limit of 15 comments
                break
            if not comment.is_private:
                comments += str(comment.text) + " "
        affects = []
        for affect in flaw.affects:
            affects.append(
                {
                    "affected": affect.affectedness,
                    "ps_module": affect.ps_module,
                    "ps_product": affect.ps_product,
                    "ps_component": affect.ps_component,
                    "impact": affect.impact,
                    "not_affected_justification": affect.not_affected_justification,
                    "delegated_not_affected_justification": affect.delegated_not_affected_justification,
                }
            )
        references = []
        for reference in flaw.references:
            if hasattr(reference, "url") and reference.url:
                references.append(
                    {
                        "url": reference.url,
                    }
                )
        cvss_scores = []
        for cvss_score in flaw.cvss_scores:
            if not (cvss_score.issuer == "RH" and "rh_cvss_score" in exclude_fields):
                cvss_scores.append(
                    {
                        "issuer": cvss_score.issuer,
                        "vector": cvss_score.vector,
                    }
                )
        # dynamically filter fields based on feature_deps injection ... note we could do something a bit more
        # clever though cvss_scores being 'out of band' decided to go with naive approach.
        return CVE(
            cve_id=flaw.cve_id,
            title="" if "title" in exclude_fields else f"{flaw.title}",
            cwe_id="" if "cwe_id" in exclude_fields else f"{flaw.cwe_id}",
            impact="" if "impact" in exclude_fields else f"{flaw.impact}",
            comment_zero=flaw.comment_zero,
            comments=f"{comments}",
            statement="" if "statement" in exclude_fields else f"{flaw.statement}",
            description=""
            if "cve_description" in exclude_fields
            else f"{flaw.cve_description}",
            components=flaw.components,
            references=references,
            affects=affects,
            cvss_scores=cvss_scores,
        )
    except Exception as e:
        logger.error(
            f"We encountered an error during OSIDB retrieval of {validated_cve_id}: {e}"
        )
        raise ValueError(f"Could not retrieve {cve_id} {e}")


@Tool
async def flaw_tool(ctx: RunContext[feature_deps], input: OSIDBToolInput) -> CVE:
    """
    Searches OSIDB by cve_id performing a lookup on CVE entity in OSIDB and returns structured information about it.

    Args:
        ctx: The RunContext provided by the Pydantic-AI agent, containing dependencies.
        cve_lookup_input: An object containing validated CVE ID (ex. CVE-2024-30941).

    Returns:
        CVE: A Pydantic model containing the CVE entity's cve_id, title, description, severity or an error message.
    """
    logger.debug(input.cve_id)
    exclude_fields = []
    if ctx.deps.exclude_osidb_fields:
        exclude_fields = ctx.deps.exclude_osidb_fields
    return await cve_retrieve(input.cve_id, exclude_fields=exclude_fields)


@Tool
async def component_count_tool(ctx: RunContext, component_name: str) -> Any:
    """
    Searches OSIDB by component_name returning count of CVE flaws related to given component.

    Args:
        ctx: The RunContext provided by the Pydantic-AI agent, containing dependencies.
        component_name: An object containing component_name (ex. curl).

    Returns:
        count: A Pydantic model containing the CVE entity's cve_id, title, description, severity or an error message.
    """
    logger.debug(component_name)
    return await client.count_component_flaws(component_name)


@Tool
async def component_flaw_tool(ctx: RunContext, component_name: str) -> Any:
    """
    Searches OSIDB by component_name returning CVE flaws related to given component.

    Args:
        ctx: The RunContext provided by the Pydantic-AI agent, containing dependencies.
        component_name: An object containing component_name (ex. curl).

    Returns:
        count: A Pydantic model containing the CVE entity's cve_id, title, description, severity or an error message.
    """
    logger.debug(component_name)
    return await client.list_component_flaws(component_name)


toolset = FunctionToolset(
    tools=[flaw_tool, component_count_tool, component_flaw_tool],
)

# osidb toolset
osidb_toolset = toolset.prefixed("osidb")
