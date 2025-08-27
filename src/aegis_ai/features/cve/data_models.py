from typing import List, Literal

from pydantic import Field, BaseModel

from aegis_ai.data_models import CVEID, CVSS3Vector, CWEID
from aegis_ai.features.data_models import AegisFeatureModel


class CVEFeatureInput(BaseModel):
    cve_id: CVEID = Field(..., description="CVE ID input")


class SuggestImpactModel(AegisFeatureModel):
    """
    Model to suggest impact of CVE.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of potentially affected components",
    )

    affected_products: List = Field(
        ...,
        description="List of Red Hat potentially affected supported products",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind suggested impact rating.
        """,
    )

    impact: Literal["LOW", "MODERATE", "IMPORTANT", "CRITICAL"] = Field(
        ..., description="Suggested Red Hat CVE impact."
    )

    cvss3_score: str = Field(
        ...,
        description="Suggested Red Hat CVSS3 score",
    )
    cvss3_vector: CVSS3Vector = Field(
        ...,
        description="Suggested Red Hat CVSS3 vector",
    )


class SuggestCWEModel(AegisFeatureModel):
    """
    Model to suggest CWE-ID of CVE.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
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
        Explain rationale behind suggested CWE-ID(s).
        """,
    )

    cwe: List[CWEID] = Field(
        ...,
        description="List of cwe-ids",
    )


class PIIReportModel(AegisFeatureModel):
    """
    Model to describe whether CVE contains PII and, if so, what instances of PII were found.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
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

    contains_PII: bool = Field(
        ...,
        description="Set to true if any PII was identified, false otherwise.",
    )


class RewriteDescriptionModel(AegisFeatureModel):
    """
    Model to rewrite CVE description.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    original_title: str = Field(
        ...,
        description="Original CVE title",
    )

    # FIXME: This field is usually empty.  Do we really need it?
    original_description: str = Field(
        ...,
        description="Original CVE description",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind rewritten CVE description and title.
        """,
    )

    rewritten_title: str = Field(..., description="rewritten CVE title.")
    rewritten_description: str = Field(..., description="rewritten CVE description.")


class RewriteStatementModel(AegisFeatureModel):
    """
    Model to rewrite Red Hat CVE statement.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    statement: List = Field(
        ...,
        description="Original CVE statement",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind rewritten description.
        """,
    )

    original_description: str = Field(
        ...,
        description="Contains the original CVE description provided by the osidb_tool.",
    )

    rewritten_statement: str = Field(
        ...,
        description="rewritten Red Hat CVE statement explaining impact on Red Hat supported products.",
    )


class CVSSDiffExplainerModel(AegisFeatureModel):
    """
    Model to explain differences between rh and nvd CVSS scores.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,
        description="Contains CVE title",
    )

    redhat_cvss3_score: str = Field(
        ...,
        description="Red Hat CVSS3 score for this CVE",
    )

    redhat_cvss3_vector: CVSS3Vector = Field(
        ...,
        description="""
        Includes Red Hat CVSS3 severity vector details for the specified Common Vulnerabilities and Exposures (CVE) identifier.
        Always include CVSS:3.1 prefix.
        
        Vector Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        
        Vector Breakdown:
        - Version: CVSS:3.1 (Common Vulnerability Scoring System)
        - Attack Characteristics:
          • Vector (AV:N): Network-based attack
          • Complexity (AC:L): Low complexity
          • Privileges (PR:N): No authentication required
          • User Interaction (UI:N): No user interaction needed
        
        Impact Metrics:
        - Confidentiality Impact (C:H): High data exposure risk
        - Integrity Impact (I:H): High system modification potential
        - Availability Impact (A:H): High service disruption likelihood
        
        Severity Assessment:
        - CVSS Score: 9.8/10.0 (Critical)
        - Risk Profile: Maximum severity
        - Potential Consequences: Remote, comprehensive system compromise
        
        Recommended Actions:
        - Immediate patch/mitigation required
        - Urgent security review
        - Comprehensive system vulnerability assessment
        """,
    )

    nvd_cvss3_score: str = Field(
        ...,
        description="nvd (NIST) CVSS3 score for this CVE",
    )

    nvd_cvss3_vector: CVSS3Vector = Field(
        ...,
        description="""        
        Includes NVD (NIST) CVSS3 severity vector details for the specified Common Vulnerabilities and Exposures (CVE) identifier.
        Always include CVSS:3.1 prefix.

        Vector Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        
        Vector Breakdown:
        - Version: CVSS:3.1 (Common Vulnerability Scoring System)
        - Attack Characteristics:
          • Vector (AV:N): Network-based attack
          • Complexity (AC:L): Low complexity
          • Privileges (PR:N): No authentication required
          • User Interaction (UI:N): No user interaction needed
        
        Impact Metrics:
        - Confidentiality Impact (C:H): High data exposure risk
        - Integrity Impact (I:H): High system modification potential
        - Availability Impact (A:H): High service disruption likelihood
        
        Severity Assessment:
        - CVSS Score: 9.8/10.0 (Critical)
        - Risk Profile: Maximum severity
        - Potential Consequences: Remote, comprehensive system compromise
        
        Recommended Actions:
        - Immediate patch/mitigation required
        - Urgent security review
        - Comprehensive system vulnerability assessment
        """,
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    affected_products: List = Field(
        ...,
        description="List of Red Hat potentially affected supported products",
    )

    statement: str = Field(..., description="redhat cve statement.")

    explanation: str = Field(
        ...,
        description="""
        Explain the difference between Red Hat and NVD(NIST) CVSS scores for this CVE.
        """,
    )
