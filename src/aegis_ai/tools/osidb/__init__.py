import logging
import os
from dataclasses import dataclass
from typing import List

from pydantic import Field

from pydantic_ai import (
    RunContext,
    Tool,
)

import osidb_bindings

from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.tools import BaseToolOutput

logger = logging.getLogger(__name__)

osidb_server_uri = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")
osidb_retrieve_embargoed = os.getenv(
    "AEGIS_OSIDB_RETRIEVE_EMBARGOED", "false"
).lower() in ("true", "1", "t", "y", "yes")


@dataclass
class OsidbDependencies:
    test = 1


class CVE(BaseToolOutput):
    """ """

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,  # Make it required
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


async def osidb_retrieve(cve_id: CVEID):
    logger.info(f"retrieving {cve_id} from osidb")
    validated_cve_id = cveid_validator.validate_python(cve_id)

    try:
        session = osidb_bindings.new_session(osidb_server_uri=osidb_server_uri)

        # Retrieval of embargoed flaws is disabled by default, to enable set env var `AEGIS_OSIDB_RETRIEVE_EMBARGOED`
        flaw = session.flaws.retrieve(
            id=validated_cve_id,
            include_fields="cve_id,title,cve_description,cvss_scores,statement,components,comments,comment_zero,affects,references,embargoed",
        )

        # This logic is about default constraining LLM access to embargo information ... for additional programmatic safety, user acl always
        # dictates if a user has access or not.
        if not osidb_retrieve_embargoed and flaw.embargoed:
            logger.info(
                f"retrieved {validated_cve_id} from osidb but it is under embargo and AEGIS_OSIDB_RETRIEVE_EMBARGOED is set 'false'."
            )
            return None

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
            cvss_scores.append(
                {
                    "issuer": cvss_score.issuer,
                    "vector": cvss_score.vector,
                }
            )
        return CVE(
            cve_id=flaw.cve_id,
            title=f"{flaw.title}",
            comment_zero=flaw.comment_zero,
            comments=f"{comments}",
            statement=f"{flaw.statement}",
            description=f"{flaw.cve_description}",
            components=flaw.components,
            references=references,
            affects=affects,
            cvss_scores=cvss_scores,
        )
    except Exception as e:
        logger.error(
            f"We encountered an error during OSIDB retrieval of {validated_cve_id}: {e}"
        )


@Tool
async def osidb_tool(ctx: RunContext[OsidbDependencies], cve_id: CVEID) -> CVE:
    """
    Searches OSIDB by cve_id performing a lookup on CVE entity in OSIDB and returns structured information about it.

    Args:
        ctx: The RunContext provided by the Pydantic-AI agent, containing dependencies.
        cve_lookup_input: An object containing validated CVE ID (e.g., CVE-2024-30941).

    Returns:
        CVE: A Pydantic model containing the CVE entity's cve_id, title, description, severity or an error message.
    """
    logger.debug(cve_id)
    return await osidb_retrieve(cve_id)
