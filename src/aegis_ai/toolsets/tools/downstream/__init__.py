"""Downstream catalog tools for SuggestManifestComponentAndState.

Wraps bomq component lookups and Anitya project queries already used by
``aegis_ai.features.cve.downstream``. Injected per-run only.
"""

from __future__ import annotations

import asyncio
import logging

from pydantic import Field
from pydantic_ai import RunContext, Tool

from aegis_ai.features.cve.downstream import (
    query_anitya_projects,
    query_bomq_components,
)
from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput

logger = logging.getLogger(__name__)


class BomqComponentsInput(BaseToolInput):
    name: str = Field(
        ...,
        description=(
            "Component name or glob for bomq components "
            "(e.g. 'openssl', '*openssl', 'openssl*', '*openssl*')."
        ),
    )
    community: bool = Field(
        default=False,
        description="Query the community bomq host when true; prod when false.",
    )


class BomqComponentsOutput(BaseToolOutput):
    name: str = Field(..., description="The name or glob that was queried.")
    community: bool = Field(..., description="Whether the community host was used.")
    components: list[dict] = Field(
        default_factory=list,
        description="Catalog rows with name, type, and build_count.",
    )


class AnityaProjectsInput(BaseToolInput):
    name: str = Field(
        ...,
        description="Exact Anitya project name to look up (case-insensitive).",
    )


class AnityaProjectsOutput(BaseToolOutput):
    name: str = Field(..., description="The project name that was queried.")
    projects: list[dict] = Field(
        default_factory=list,
        description="Matching Anitya projects with backend, homepage, and Fedora packages.",
    )


@Tool
async def bomq_components_tool(
    ctx: RunContext, input: BomqComponentsInput
) -> BomqComponentsOutput:
    """List bomq component catalog rows for a name or glob on prod or community."""
    logger.info(
        "bomq_components_tool name=%s community=%s", input.name, input.community
    )
    components = await asyncio.to_thread(
        query_bomq_components,
        input.name,
        glob="*" in input.name,
        community=input.community,
    )
    return BomqComponentsOutput(
        name=input.name,
        community=input.community,
        components=components,
    )


@Tool
async def anitya_projects_tool(
    ctx: RunContext, input: AnityaProjectsInput
) -> AnityaProjectsOutput:
    """Look up Anitya projects by exact name and list Fedora/EPEL package names."""
    logger.info("anitya_projects_tool name=%s", input.name)
    projects = await asyncio.to_thread(query_anitya_projects, input.name)
    return AnityaProjectsOutput(name=input.name, projects=projects)
