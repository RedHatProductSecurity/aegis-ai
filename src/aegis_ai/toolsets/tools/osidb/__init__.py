import logging

from typing import List, Any, Optional

from pydantic import Field

from pydantic_ai import (
    RunContext,
    Tool,
)
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai import get_env_flag
from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools import BaseToolOutput, BaseToolInput
from aegis_ai.toolsets.tools.osidb.osidb_client import OSIDBClient

logger = logging.getLogger(__name__)

OSIDB_RETRIEVE_EMBARGOED = get_env_flag("AEGIS_OSIDB_RETRIEVE_EMBARGOED", False)


client = OSIDBClient()


class OSIDBToolInput(BaseToolInput):
    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )


class CVE(BaseToolOutput):
    """data model used to retrieve security flaw data from OSIDB"""

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw",
    )
    cwe_id: Optional[str] = Field(
        default="",
        description="CVE CWE ID",
    )
    impact: Optional[str] = Field(
        default="",
        description="CVE impact",
    )
    title: str = Field(
        default="",
        description="CVE title",
    )
    statement: Optional[str] = Field(
        default="",
        description="CVE statement",
    )
    mitigation: Optional[str] = Field(
        default="",
        description="CVE mitigation",
    )
    comment_zero: str = Field(
        default="",
        description="CVE comment_zero",
    )
    comments: str = Field(
        default="",
        description="all public comments",
    )
    description: str = Field(
        default="",
        description="CVE cve_description",
    )
    components: List = Field(
        default=[],
        description="list of components",
    )
    references: List = Field(
        default=[],
        description="list of references",
    )
    affects: List = Field(
        default=[],
        description="list of affects",
    )
    cvss_scores: List = Field(
        default=[],
        description="list of cvss scores",
    )


def cve_exclude_fields(cve: CVE, exclude_fields: List[str]):
    """return a CVE object with data removed in fields specified by exclude_fields"""
    # "cve_description" is used in OSIM, "description" is used in OSIDB
    fields_to_exclude = set(
        [field.replace("cve_description", "description") for field in exclude_fields]
    )

    # create a local copy so that we can change the CVE object
    cve = cve.model_copy()
    if "rh_cvss_score" in fields_to_exclude:
        # exclude RH-provided CVSS
        cve.cvss_scores = [cvss for cvss in cve.cvss_scores if cvss["issuer"] != "RH"]

    # finally remove all fields listed in fields_to_exclude
    filtered_dump = cve.model_dump(exclude=fields_to_exclude)
    return CVE(**filtered_dump)


async def cve_retrieve(cve_id: CVEID) -> CVE:
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

        cvss_scores = [
            {
                "issuer": score.issuer,
                "vector": score.vector,
            }
            for score in flaw.cvss_scores
        ]

        return CVE(
            cve_id=flaw.cve_id,
            title=flaw.title,
            cwe_id=flaw.cwe_id,
            impact=flaw.impact,
            comment_zero=flaw.comment_zero,
            comments=f"{comments}",
            statement=flaw.statement,
            mitigation=flaw.mitigation,
            description=flaw.cve_description,
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
    cve = await cve_retrieve(input.cve_id)

    # exclude CVE fields according to feature_deps
    return cve_exclude_fields(cve, ctx.deps.exclude_osidb_fields)


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
