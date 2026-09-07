"""Build system toolset for binary RPM subpackage enumeration.

Queries the Deptopia REST API to resolve a source package + product stream
to a Brew build NVR, then uses the Koji/Brew API to list the binary RPM
names produced by that build.
"""

import asyncio
import json
import logging
import urllib.error
import urllib.request

import koji
from pydantic import Field
from pydantic_ai import RunContext, Tool

from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput

logger = logging.getLogger(__name__)

DEPTOPIA_API = "https://deptopia.prodsec.redhat.com/api/v1/incoming/search"
BREW_PROFILE = "brew"


class ListBinaryRPMsInput(BaseToolInput):
    package: str = Field(
        ...,
        description="Source RPM package name (e.g., 'curl', 'kernel').",
    )
    ps_update_stream: str = Field(
        ...,
        description="Product stream update identifier (e.g., 'rhel-9.6.0.z').",
    )


class ListBinaryRPMsOutput(BaseToolOutput):
    package: str = Field(
        ...,
        description="The source RPM package name that was queried.",
    )
    ps_update_stream: str = Field(
        ...,
        description="The product stream that was queried.",
    )
    binary_rpms: list[str] = Field(
        default_factory=list,
        description="Sorted list of unique binary RPM names produced by this source package in the given stream.",
    )
    build_nvr: str | None = Field(
        default=None,
        description="The NVR (name-version-release) of the resolved build, if found.",
    )


def _create_brew_session() -> koji.ClientSession:
    """Create a Koji/Brew client session using the brew profile."""
    config = koji.read_config(BREW_PROFILE)
    session_opts = koji.grab_session_options(config)
    return koji.ClientSession(config["server"], session_opts)


def _resolve_build_from_stream(
    session: koji.ClientSession, package: str, ps_update_stream: str
) -> tuple[int, str] | None:
    """Query Deptopia for a build NVR, then resolve it to a Koji build ID.

    Returns (build_id, build_nvr) or None if no matching build is found.
    """
    url = f"{DEPTOPIA_API}?build_name={package}&strict_builds=true"
    resp = urllib.request.urlopen(url)
    data = json.loads(resp.read())

    matches = [
        b
        for b in data.get("Builds", [])
        if b.get("ps_update_stream") == ps_update_stream
    ]
    if not matches:
        return None

    nvr = matches[0]["build_nvr"]
    build = session.getBuild(nvr)
    if not build:
        return None

    return build["id"], nvr


def _list_binary_rpms(session: koji.ClientSession, build_id: int) -> list[str]:
    """List binary RPM names for a build, excluding source RPMs."""
    rpms = session.listRPMs(buildID=build_id)
    return sorted({r["name"] for r in rpms if r["arch"] != "src"})


def _lookup_binary_rpms(package: str, ps_update_stream: str) -> ListBinaryRPMsOutput:
    """Synchronous lookup of binary RPMs (runs in a thread)."""
    try:
        session = _create_brew_session()
    except koji.ConfigurationError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="error",
            error_message=f"Koji profile '{BREW_PROFILE}' not configured: {e}",
        )

    try:
        result = _resolve_build_from_stream(session, package, ps_update_stream)
    except urllib.error.HTTPError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="error",
            error_message=f"Deptopia API error: {e.code} {e.reason}",
        )
    except urllib.error.URLError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="error",
            error_message=f"Deptopia API error: {e.reason}",
        )
    except koji.GenericError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="error",
            error_message=f"Koji/Brew error: {e}",
        )

    if result is None:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="not_found",
            error_message=f"No builds found for package '{package}' in stream '{ps_update_stream}'",
        )

    build_id, build_nvr = result

    try:
        binary_rpms = _list_binary_rpms(session, build_id)
    except koji.GenericError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            build_nvr=build_nvr,
            status="error",
            error_message=f"Koji/Brew error listing RPMs: {e}",
        )

    return ListBinaryRPMsOutput(
        package=package,
        ps_update_stream=ps_update_stream,
        binary_rpms=binary_rpms,
        build_nvr=build_nvr,
    )


@Tool
async def list_binary_rpms_tool(
    ctx: RunContext, input: ListBinaryRPMsInput
) -> ListBinaryRPMsOutput:
    """Look up the binary RPM subpackage names produced by a source RPM package
    in a given product stream. Use this tool to determine which binary artifacts
    are built from a source package, helping assess binary-level affectedness.
    Requires a source package name (from the PURL) and a ps_update_stream
    (from the OSIDB affect entry)."""
    logger.info(
        "[build_system_tool] Looking up binary RPMs for %s in stream %s...",
        input.package,
        input.ps_update_stream,
    )
    return await asyncio.to_thread(
        _lookup_binary_rpms, input.package, input.ps_update_stream
    )
