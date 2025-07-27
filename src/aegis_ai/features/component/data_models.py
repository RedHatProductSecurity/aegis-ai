from pydantic import Field, BaseModel

from aegis_ai.features.data_models import AegisFeatureModel


class ComponentFeatureInput(BaseModel):
    component_name: str = Field(..., description="component name")


class ComponentIntelligenceModel(AegisFeatureModel):
    """
    Model containing information on a software component.
    """

    component_name: str = Field(
        ...,
        description="Contains component name",
    )

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
