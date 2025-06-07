import logging
import os
import re
from dataclasses import dataclass
from typing import List

from pydantic import BaseModel, Field
from pydantic import field_validator

from pydantic_ai import (
    RunContext,
    Tool,
)

import osidb_bindings

from aegis.tools import BaseToolOutput

logger = logging.getLogger(__name__)

osidb_server_uri = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")


@dataclass
class OsidbDependencies:
    test = 1


class CVE(BaseToolOutput):
    """ """

    cve_id: str = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw. "
        "This is the primary identifier for the vulnerability within OSIDB (e.g., 'CVE-2024-3094').",
    )
    title: str = Field(
        ...,  # Make it required
        description="CVE title.",
    )
    statement: str = Field(
        None,
        description="CVE statement.",
    )
    comment_zero: str = Field(None, description="CVE comment_zero.")
    comments: str = Field(
        None,
        description="all public comments.",
    )
    description: str = Field(None, description="CVE cve_description.")
    components: List = Field(..., description="list of components")
    references: List = Field(..., description="list of references")
    affects: List = Field(..., description="list of affects")
    cvss_scores: List = Field(..., description="list of cvss scores")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id_format(cls, v: str) -> str:
        """
        Validates that the CVE ID adheres to the CVE-YYYY-XXXXX format.
        """
        cve_regex = r"^CVE-\d{4}-\d{4,6}$"
        if not re.match(cve_regex, v):
            raise ValueError(
                "Invalid CVE ID format. Expected format: CVE-YYYY-XXXXX (e.g., CVE-2024-30941)."
            )
        return v


class OsidbLookupInput(BaseModel):
    """
    Input schema for the osidb_lookup tool, enforcing CVE ID format.
    """

    cve_id: str = Field(
        ..., description="The CVE ID of the vulnerability (e.g., CVE-2024-30941)."
    )

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id_format(cls, v: str) -> str:
        """
        Validates that the CVE ID adheres to the CVE-YYYY-XXXXX format.
        """
        cve_regex = r"^CVE-\d{4}-\d{4,6}$"
        if not re.match(cve_regex, v):
            raise ValueError(
                "Invalid CVE ID format. Expected format: CVE-YYYY-XXXXX (e.g., CVE-2024-30941)."
            )
        return v


async def osidb_retrieve(cve_id: str):
    logger.debug(f"retrieving {cve_id} from osidb")
    try:
        session = osidb_bindings.new_session(osidb_server_uri=osidb_server_uri)
        flaw = session.flaws.retrieve(
            id=cve_id,
            include_fields="cve_id,title,cve_description,cvss_scores,statement,components,comments,comment_zero,affects,references,",
        )

        logger.info(f"successfully retrieved {cve_id}:{flaw.title}")

        comments = ""
        for comment in flaw.comments:
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
        logger.error(f"We encountered an error during OSIDB retrieval: {e}")


@Tool
async def osidb_lookup(
    ctx: RunContext[OsidbDependencies], cve_lookup_input: OsidbLookupInput
) -> CVE:
    """
    Searches OSIDB by cve_id performing a lookup on CVE entity in OSIDB and returns structured information about it.

    Args:
        ctx: The RunContext provided by the Pydantic-AI agent, containing dependencies.
        cve_lookup_input: An object containing the validated CVE ID (e.g., CVE-2024-30941).

    Returns:
        CVE: A Pydantic model containing the CVE entity's cve_id, title, description, severity or an error message.
    """
    flaw = osidb_retrieve(cve_lookup_input.cve_id)
    return flaw
