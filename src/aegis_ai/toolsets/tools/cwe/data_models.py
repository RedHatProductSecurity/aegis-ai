from typing import List, Optional

from pydantic import Field

from aegis_ai.data_models import CWEID
from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput


class CWEToolInput(BaseToolInput):
    """CWE tool input"""

    cwe_ids: List[CWEID] = Field(
        ...,
        description="Array of unique CWE identifiers.",
    )


class CWESearchInput(BaseToolInput):
    """Input for searching CWEs with a natural language query."""

    query: str = Field(
        ...,
        description="The natural language query to search for relevant CWEs.",
        min_length=3,
        max_length=100,
    )


class CWE(BaseToolOutput):
    """Canonical CWE definition returned by the `cwe_tool`."""

    cwe_id: CWEID = Field(
        ...,
        description="The unique CWE identifier for the security CWE.",
    )

    name: str = Field(
        ...,
        description="CWE name.",
    )

    description: str = Field(
        ...,
        description="CWE description.",
    )

    extended_description: str = Field(
        ...,
        description="CWE extended_description.",
    )

    affected_resources: str = Field(
        ...,
        description="CWE affected_resources.",
    )

    notes: str = Field(
        ...,
        description="CWE notes.",
    )

    disallowed: bool = Field(
        ...,
        description="True if the CWE is not available in the CWE-699 view.",
    )

    score: Optional[float] = Field(
        0,
        ge=0.0,
        le=1.0,
        description="Similarity search score",
    )
