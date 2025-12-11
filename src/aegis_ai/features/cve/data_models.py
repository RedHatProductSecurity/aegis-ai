import logging
from typing import List, Literal, Optional

from pydantic import Field, BaseModel, field_validator, ValidationInfo

from aegis_ai.data_models import CVEID, CVSS3Vector, CWEID
from aegis_ai.features.data_models import AegisFeatureModel
from aegis_ai.toolsets.tools.cwe import cwe_manager


class CVEFeatureInput(BaseModel):
    cve_id: CVEID = Field(..., description="CVE ID input")


class CVEDataCriticOutput(AegisFeatureModel):
    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    explanation: str = Field(
        ...,
        description="Data critique on quality, completeness and consistency of CVE data.",
    )


class SuggestImpactModel(AegisFeatureModel):
    """
    Represents a model-generated suggestion for the CVSS 3.1 score and related impact
    of a specific CVE. This data structure is used to assist security
    analysts in triaging and rating vulnerabilities by providing a
    pre-computed assessment.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,
        description="CVE title",
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
        description="Explain rationale behind suggested CVSS 3.1 score and impact rating.",
    )

    impact: Optional[Literal["LOW", "MODERATE", "IMPORTANT", "CRITICAL"]] = Field(
        description="Suggested Red Hat CVE impact",
    )

    cvss3_score: str = Field(
        ...,
        description="Suggested Red Hat CVSS3.1 score",
    )

    cvss3_vector: Optional[CVSS3Vector] = Field(
        description="Suggested Red Hat CVSS3.1 vector",
    )

    def printable_outcome(self) -> str:
        """override the logging hook to print the resulting suggestion"""
        return f"{self.impact} {self.cvss3_score} {self.cvss3_vector}"


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

    @field_validator("cwe")
    @classmethod
    def filter_allowed_cwes(
        cls, unfiltered_cwes: List[CWEID], info: ValidationInfo
    ) -> List[CWEID]:
        allowed_cwe_ids = set(cwe_manager.get_allowed_cwe_ids())
        filtered_out = set(unfiltered_cwes) - allowed_cwe_ids
        if not filtered_out:
            # we should not get disallowed CWEs on the LLM output under normal circumstances
            return unfiltered_cwes

        cve_id = info.data.get("cve_id")
        f_list = list(filtered_out)
        logging.warning(f"{cve_id}: filtering out disallowed CWE IDs: {f_list}")
        return [cwe for cwe in unfiltered_cwes if cwe not in filtered_out]

    def printable_outcome(self) -> str:
        """override the logging hook to print the resulting CWE list"""
        return str(self.cwe)


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


class SuggestDescriptionModel(AegisFeatureModel):
    """
    Model to suggest CVE description.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    components: List = Field(
        ...,
        description="list of affected components",
    )

    explanation: str = Field(
        ...,
        description="Explain rationale behind suggested CVE description and title.",
    )

    suggested_title: str = Field(
        ...,
        description="suggested CVE title",
    )

    suggested_description: str = Field(
        ...,
        description="suggested CVE description",
    )


class SuggestStatementModel(AegisFeatureModel):
    """
    Model to suggest Red Hat CVE statement and mitigation.
    """

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    title: str = Field(
        ...,
        description="CVE title",
    )

    impact: Literal["", "LOW", "MODERATE", "IMPORTANT", "CRITICAL"] = Field(
        ...,
        description="CVE impact",
    )

    components: List = Field(
        ...,
        description="List of affected components",
    )

    description: str = Field(
        ...,
        description="CVE description",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind suggested description.
        """,
    )

    suggested_statement: Optional[str] = Field(
        description="suggested Red Hat CVE statement explaining impact on Red Hat supported products.",
    )

    suggested_mitigation: Optional[str] = Field(
        description="suggested Red Hat CVE mitigation explaining how to mitigate impact on Red Hat supported products.",
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
