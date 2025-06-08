from typing import List

from pydantic import BaseModel, Field


class AegisFeatureModel(BaseModel):
    """
    Metadata for Aegis features, nested within the main feature model.
    """

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="A score between 0.00 and 1.00 (two decimal places) indicating confidence in the analysis. A higher score means greater certainty.",
    )

    tools_used: List = Field(
        ...,
        description="he name of the tool, if any, that was used to formulate this answer. If this is a suggest or rewrite feature then should minimally include 'osidb_tool'",
    )


class AegisAnswer(AegisFeatureModel):
    """
    Default answer response.
    """

    explanation: str = Field(
        ...,
        description="A brief rationale explaining how the answer was generated, what sources were primary, and if the answer was provided directly by the LLM or not. Do not repeat the answer here.",
    )

    answer: str = Field(..., description="The direct answer to the user's question.")
