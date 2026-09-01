from typing import Any, Literal

from pydantic import BaseModel, Field, PrivateAttr, model_validator

from aegis_ai.data_models import CVEID, CWEID, CVSS3Vector
from aegis_ai.features.data_models import AegisFeatureModel


class CVEFeatureInput(BaseModel):
    cve_id: CVEID = Field(..., description="CVE ID input")
    title: str | None = Field(None, description="CVE title")
    description: str | None = Field(None, description="CVE description")
    cwe_id: str | None = Field(None, description="CVE CWE ID")
    impact: str | None = Field(None, description="CVE impact")
    statement: str | None = Field(None, description="CVE statement")
    mitigation: str | None = Field(None, description="CVE mitigation")
    comment_zero: str | None = Field(None, description="CVE comment_zero")
    comments: list | str | None = Field(None, description="All public comments")
    components: list | None = Field(None, description="List of components")
    references: list | None = Field(None, description="List of references")
    affects: list | None = Field(None, description="List of affects")
    cvss_scores: list | None = Field(None, description="List of CVSS scores")

    def __repr__(self) -> str:
        fields = {k: v for k, v in self.__dict__.items() if v is not None}
        pairs = " ".join(f"{k}={v!r}" for k, v in fields.items())
        return f"{self.__class__.__name__}({pairs})"

    def __str__(self) -> str:
        return self.__repr__()


class CVEDataCriticOutput(AegisFeatureModel):
    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    explanation: str = Field(
        ...,
        description="Data critique on quality, completeness and consistency of CVE data.",
    )


class AffectedComponentEntry(BaseModel):
    """A single affected component with its update stream and PURL."""

    ps_update_stream: str = Field(
        ...,
        description="The product stream update identifier (e.g., 'rhel-9.6.0.z').",
    )

    purl: str = Field(
        ...,
        description="Package URL identifying the source RPM package.",
    )


class QueryAffectedComponentsModel(BaseModel):
    """Deterministic query result: affected components from OSIDB affects."""

    cve_id: CVEID = Field(
        ...,
        description="The CVE identifier that was queried.",
    )

    affected_components: list[AffectedComponentEntry] = Field(
        default_factory=list,
        description="List of affected components with their update streams and PURLs.",
    )

    disclaimer: Literal[
        "This is an experimental feature and its interface may change in future versions."
    ] = "This is an experimental feature and its interface may change in future versions."

    def printable_outcome(self) -> str:
        return f"{len(self.affected_components)} affected component(s)"


class AffectedPackageEntry(BaseModel):
    """A single package-level affectedness suggestion with rationale."""

    purl: str = Field(
        ...,
        description="Package URL identifying the source RPM package.",
    )

    ps_update_stream: str = Field(
        ...,
        description="The product stream update identifier (e.g., 'rhel-9.6.0.z').",
    )

    affected: bool = Field(
        ...,
        description="Whether this source RPM package is affected by the vulnerability.",
    )

    explanation: str = Field(
        ...,
        description="Per-package rationale for the affectedness determination.",
    )

    affected_subcomponents: str | None = Field(
        default=None,
        description="Optional free-text hint about which internal components within "
        "the package are affected (e.g., 'XFS kernel module', 'libcurl HTTP/2 handler').",
    )


class SuggestAffectedPackagesModel(AegisFeatureModel):
    """LLM-driven suggestion of source RPM package affectedness."""

    cve_id: CVEID = Field(
        ...,
        description="The CVE identifier for the analyzed flaw.",
    )

    affected_packages: list[AffectedPackageEntry] = Field(
        default_factory=list,
        description="Per-package affectedness suggestions with PURLs and rationale.",
    )

    explanation: str = Field(
        ...,
        description="Overall rationale for the affectedness analysis.",
    )

    def printable_outcome(self) -> str:
        affected = sum(1 for p in self.affected_packages if p.affected)
        total = len(self.affected_packages)
        return f"{affected}/{total} package(s) affected"


class SuggestAffectedComponentsModel(AegisFeatureModel):
    """Model for suggested affected components inferred from CVE data."""

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    components: list[str] = Field(
        ...,
        description="Suggested affected component names.",
    )

    ecosystems: list[str] = Field(
        default_factory=list,
        description="Package ecosystems impacted by this vulnerability. "
        "Allowed values: cargo, golang, npm, pypi, maven, gem, upstream, unknown.",
    )

    explanation: str = Field(
        ...,
        description="Rationale for component suggestions.",
    )

    def printable_outcome(self) -> str:
        """Override the logging hook to print the resulting suggestion."""
        if self.ecosystems:
            return f"{self.components} ecosystems={self.ecosystems}"
        return str(self.components)


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

    explanation: str = Field(
        ...,
        description="Explain rationale behind suggested CVSS 3.1 score and impact rating.",
    )

    impact: Literal["LOW", "MODERATE", "IMPORTANT", "CRITICAL"] | None = Field(
        description="Suggested Red Hat CVE impact",
    )

    cvss3_score: str = Field(
        ...,
        description="Suggested Red Hat CVSS3.1 score",
    )

    cvss3_vector: CVSS3Vector | None = Field(
        description="Suggested Red Hat CVSS3.1 vector",
    )

    deescalation_rationale: str | None = Field(
        default=None,
        exclude=True,
        description=(
            "If you are rating impact LOWER than the standard CVSS band would suggest, "
            "explain the Red Hat policy justification here (e.g., 'AV:L + C:N/I:N + "
            "contained BPF subsystem = MODERATE despite 7.5 CVSS'). "
            "Leave empty/null when impact matches the standard CVSS band."
        ),
    )

    classifier_disagreement_rationale: str | None = Field(
        default=None,
        exclude=True,
        description=(
            "If the kernel_impact_tool predicted a DIFFERENT severity than your "
            "assessment, explain why you disagree (e.g., 'classifier predicted "
            "IMPORTANT but AV:P + s390-specific hardware limits real-world exposure "
            "to MODERATE'). Leave empty/null when your impact matches the classifier "
            "prediction or no classifier result is available."
        ),
    )

    _flags: list[str] = PrivateAttr(default_factory=list)
    _classifier_diagnostics: dict[str, Any] | None = PrivateAttr(default=None)
    _reconciliation_trace: str | None = PrivateAttr(default=None)
    _escalation_floor_applied: bool = PrivateAttr(default=False)
    _original_llm_impact: str | None = PrivateAttr(default=None)
    _original_llm_score: str | None = PrivateAttr(default=None)
    _original_llm_vector: str | None = PrivateAttr(default=None)
    _explanation_revised: bool = PrivateAttr(default=False)

    def printable_outcome(self) -> str:
        """override the logging hook to print the resulting suggestion"""
        return f"{self.impact} {self.cvss3_score} {self.cvss3_vector}"


class RevisedExplanationModel(BaseModel):
    """Lightweight model for the follow-up LLM call that revises the
    explanation after post-processing adjusted score or impact."""

    explanation: str = Field(
        ...,
        description="Revised explanation consistent with the adjusted CVSS score and impact.",
    )


class SuggestCWEModel(AegisFeatureModel):
    """
    Model to suggest CWE-ID of CVE.
    """

    cve_id: CVEID = Field(
        ...,  # Make it required
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind suggested CWE-ID(s).
        """,
    )

    cwe: list[CWEID] = Field(
        ...,
        description="List of cwe-ids",
    )

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

    components: list = Field(
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

    suggested_statement: str | None = Field(
        description="suggested Red Hat CVE statement explaining impact on Red Hat supported products.",
    )

    suggested_mitigation: str | None = Field(
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

    statement: str = Field(..., description="redhat cve statement.")

    explanation: str = Field(
        ...,
        description="""
        Explain the difference between Red Hat and NVD(NIST) CVSS scores for this CVE.
        """,
    )


# ---------------------------------------------------------------------------
# Quality Review models
# ---------------------------------------------------------------------------


# Category weights from the FQI rubric specification.
# Each category has 5 criteria scored 0-2 (max 10 raw points).
# The weighted final score is on a 0.0-1.0 scale.
CATEGORY_WEIGHTS: dict[str, float] = {
    "Description - Technical Clarity": 0.20,
    "Statement - Technical Clarity": 0.25,
    "Mitigation": 0.10,
    "Grammar & Style": 0.15,
    "Content Ambiguity": 0.15,
    "Technical Value": 0.15,
}


# Quality rating constants and type for the weighted 0.0-1.0 score.
# Using Literal instead of Enum to avoid $defs in JSON schema, which
# causes 400 errors with Mistral's grammar-based structured output.
QualityRating = Literal["Excellent", "Good", "Needs Improvement", "Fails Standards"]

RATING_EXCELLENT: QualityRating = "Excellent"
RATING_GOOD: QualityRating = "Good"
RATING_NEEDS_IMPROVEMENT: QualityRating = "Needs Improvement"
RATING_FAILS_STANDARDS: QualityRating = "Fails Standards"


class QualityReviewModel(AegisFeatureModel):
    """
    Quality review of CVE flaw content scored against a weighted rubric
    with 6 categories (30 criteria), evaluated through a Customer Lens framework.
    Final score is on a 0.0-1.0 weighted scale per the FQI specification.

    Note: All fields use primitive types (no nested BaseModel classes) to avoid
    $defs/$ref in the JSON schema, which Mistral's grammar-based structured
    output cannot resolve.
    """

    cve_id: CVEID = Field(
        ...,
        description="The CVE identifier for the reviewed flaw.",
    )

    overall_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weighted score on a 0.0-1.0 scale (auto-computed from criterion scores).",
    )

    rating: QualityRating = Field(
        default=RATING_FAILS_STANDARDS,
        description="Quality rating derived from overall_score (auto-computed).",
    )

    scores: list[dict[str, Any]] = Field(
        ...,
        description="Flat list of all criterion scores across all 6 rubric categories. "
        "Each entry is an object with: category (string), criterion_id (string), "
        "score (integer 0-2), and justification (string).",
    )

    customer_can_decide: list[str] = Field(
        ...,
        description="What a customer CAN decide from the current content.",
    )
    remains_unclear: list[str] = Field(
        ...,
        description="What REMAINS UNCLEAR from the current content.",
    )
    manual_context_needed: list[str] = Field(
        ...,
        description="What additional context an analyst would need to add MANUALLY.",
    )

    strengths: list[str] = Field(
        ...,
        description="Notable strengths of the flaw content.",
    )

    critical_gaps: list[str] = Field(
        ...,
        description="Critical gaps that must be addressed.",
    )

    recommendations: list[str] = Field(
        ...,
        description="Actionable recommendations to improve the content.",
    )

    suggested_statement: str | None = Field(
        default=None,
        description="Suggested rewrite of the statement when current content scores poorly.",
    )

    suggested_mitigation: str | None = Field(
        default=None,
        description="Suggested rewrite of the mitigation when current content scores poorly.",
    )

    value_add: str = Field(
        ...,
        description="Whether this assessment provides information customers cannot find elsewhere.",
    )

    explanation: str = Field(
        ...,
        description="Brief summary of the quality review findings, highlighting the most significant strengths and gaps.",
    )

    @model_validator(mode="after")
    def compute_overall_score_and_rating(self) -> "QualityReviewModel":
        """Auto-compute weighted overall_score and rating from criterion scores.

        Groups criterion scores by category, sums each category's raw points
        (0-10), then applies FQI category weights to produce a 0.0-1.0 score.
        """
        # Sum raw points per category
        cat_raw: dict[str, int] = {}
        for c in self.scores:
            cat_raw[c["category"]] = cat_raw.get(c["category"], 0) + c["score"]

        # Compute weighted score: sum(category_raw / 10.0 * weight)
        weighted = 0.0
        for cat_name, weight in CATEGORY_WEIGHTS.items():
            raw = min(cat_raw.get(cat_name, 0), 10)  # clamp to max 10 per category
            weighted += (raw / 10.0) * weight
        self.overall_score = round(weighted, 2)

        # Derive rating from weighted score
        if self.overall_score >= 0.8:
            self.rating = RATING_EXCELLENT
        elif self.overall_score >= 0.6:
            self.rating = RATING_GOOD
        elif self.overall_score >= 0.4:
            self.rating = RATING_NEEDS_IMPROVEMENT
        else:
            self.rating = RATING_FAILS_STANDARDS
        return self

    def printable_outcome(self) -> str:
        """Override the logging hook to print the quality score and rating."""
        return f"score={self.overall_score}/1.0 ({self.rating})"
