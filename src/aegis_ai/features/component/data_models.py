from typing import List, Optional

from pydantic import Field, BaseModel, model_validator

from aegis_ai.features.data_models import AegisFeatureModel

# Canonical component names: map common LLM variants to OSIDB/cache-style names.
COMPONENT_NAME_ALIASES: dict[str, str] = {
    "linux kernel": "kernel",
}


def _normalize_component_name(name: str) -> str:
    """Rewrite known aliases to canonical form (e.g. 'Linux kernel' -> 'kernel')."""
    if not name or not isinstance(name, str):
        return name
    key = name.strip().lower()
    return COMPONENT_NAME_ALIASES.get(key, name.strip())


class ComponentFeatureInput(BaseModel):
    """Input for Component Intelligence: either component_name or (title + description)."""

    component_name: Optional[str] = Field(
        default=None,
        description="Component name for lookup mode.",
    )
    title: Optional[str] = Field(
        default=None,
        description="CVE or vulnerability title for component-suggestion mode.",
    )
    description: Optional[str] = Field(
        default=None,
        description="CVE or vulnerability description for component-suggestion mode.",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Optional CVE ID for this vulnerability (e.g. CVE-2024-3782). When set, the agent should use this ID for OSIDB lookups.",
    )

    @model_validator(mode="after")
    def require_component_name_or_title_description(self):
        has_name = self.component_name is not None and self.component_name.strip() != ""
        has_title = self.title is not None and self.title.strip() != ""
        has_desc = self.description is not None and self.description.strip() != ""
        if has_name and (has_title or has_desc):
            raise ValueError(
                "Provide either component_name or (title and description), not both."
            )
        if not has_name and not (has_title and has_desc):
            raise ValueError(
                "Provide either component_name or both title and description."
            )
        return self


class ComponentIntelligenceModel(AegisFeatureModel):
    """
    Model containing information on a software component.
    """

    component_name: str = Field(
        ...,
        description="Primary component name (requested component or first suggested).",
    )

    components: List[str] = Field(
        ...,
        description="List of suggested or related component names.",
    )

    @model_validator(mode="after")
    def canonicalize_component_names(self) -> "ComponentIntelligenceModel":
        """Rewrite known aliases to canonical form (e.g. 'Linux kernel' -> 'kernel')."""
        self.component_name = _normalize_component_name(self.component_name)
        normalized = [_normalize_component_name(c).lower() for c in self.components]
        # Dedupe while preserving order (e.g. ["Linux kernel", "kernel"] -> ["kernel"])
        self.components = list(dict.fromkeys(n for n in normalized if n))
        return self

    component_latest_version: str = Field(
        ...,
        description="Contains component latest version",
    )

    component_purl: str = Field(
        ...,
        description="Contains component purl",
    )

    website_url: str = Field(
        ...,
        description="Contains component project website.",
    )
    repo_url: str = Field(
        ...,
        description="Contains component repository url (ex. github).",
    )
    popularity_score: int = Field(
        ...,
        ge=1,
        le=10,
        description="Contains component popularity scale of 1 to 10, with 1 being most popular and 10 being not used at all.",
    )

    stability_score: int = Field(
        ...,
        ge=1,
        le=10,
        description="Contains component project stability scale of 1 to 10, with 1 being most stable and 10 not stable at all.",
    )

    recent_news: str = Field(
        ...,
        description="Contains component recent news.",
    )

    active_contributors: str = Field(
        ...,
        description="Contains component active contributors.",
    )

    security_information: str = Field(
        ...,
        description="Contains component security related information.",
    )

    further_learning: str = Field(
        ...,
        description="Contains component further learning.",
    )
    explanation: str = Field(
        ...,
        description="""
        Explain rationale behind component software analysis.
        """,
    )
