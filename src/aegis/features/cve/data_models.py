from typing import List, Literal

from pydantic import BaseModel, Field


class SuggestImpactModel(BaseModel):
    """
    Model to suggest impact of CVE.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind suggested impact rating.
        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis is correct. A higher score means greater certainty.",
    )

    impact: Literal["LOW", "MODERATE", "IMPORTANT", "CRITICAL"] = Field(
        ..., description="Suggested CVE impact."
    )


class SuggestCWEModel(BaseModel):
    """
    Model to suggest CWE-ID of CVE.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind suggested CWE-ID.
        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis is correct. A higher score means greater certainty.",
    )

    impact: str = Field(..., description="Suggested CWE-ID.")


class PIIReportModel(BaseModel):
    """
    Model to describe whether CVE contains PII and, if so, what instances of PII were found.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""If PII is found, create a bulleted list where each item is formatted as PII type:"exact string". If no PII is found, leave this section empty.

        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the PII analysis is correct. A higher score means greater certainty.",
    )

    contains_PII: bool = Field(
        ...,
        description="Set to true if any PII was identified, false otherwise.",
    )


class RewriteDescriptionModel(BaseModel):
    """
    Model to rewrite CVE description.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    original_title: str = Field(
        ...,
        description="Contains CVE title",
    )

    original_description: List = Field(
        ...,
        description="Original cve description",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind rewritten description.
        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis is correct. A higher score means greater certainty.",
    )

    rewritten_description: str = Field(..., description="rewritten cve description.")

    rewritten_title: str = Field(..., description="rewritten cve title.")


class RewriteStatementModel(BaseModel):
    """
    Model to rewrite CVE statement.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    original_statement: List = Field(
        ...,
        description="Original cve statement",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind rewritten description.
        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis is correct. A higher score means greater certainty.",
    )

    statement: str = Field(..., description="rewritten cve statement.")


class CVSSDiffExplainerModel(BaseModel):
    """
    Model to explain differences between rh and nvd CVSS scores.
    """

    cve_id: str = Field(
        ...,
        description="Contains CVE id",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    redhat_cvss_score: str = Field(
        ...,
        description="Contains Red Hat cvss score for this CVE.",
    )

    nvd_cvss_score: str = Field(
        ...,
        description="Contains nvd cvss score for this CVE.",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain the difference between rh and nvd CVSS scores for this CVE.
        """,
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis is correct. A higher score means greater certainty.",
    )

    redhat_statement: str = Field(..., description="redhat cve statement.")
