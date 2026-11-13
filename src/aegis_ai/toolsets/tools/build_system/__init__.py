"""Build system toolset for binary RPM subpackage enumeration.

Queries the bomq REST API to resolve a source package + product stream
to a Brew build NVR, then uses the Koji/Brew API to list the binary RPM
names produced by that build.
"""

import asyncio
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import koji
from pydantic import Field
from pydantic_ai import RunContext, Tool

from aegis_ai import get_settings
from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput

logger = logging.getLogger(__name__)

BOMQ_API_PATH = "/api/v0/search/builds"
BREW_PROFILE = "brew"

_EXCLUDED_RPM_PATTERNS = re.compile(
    r"^glibc-(all-langpacks|langpack-|minimal-langpack)|-debuginfo(-|$)|-debugsource$"
)

BREW_MAX_CONCURRENT = 4
ENRICHMENT_TIMEOUT_SECS = 60
_brew_sem = threading.Semaphore(BREW_MAX_CONCURRENT)


def _remaining(deadline: float | None) -> float:
    """Return seconds left until *deadline*, raising on expiry."""
    if deadline is None:
        return 30.0
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("build system lookup deadline exceeded")
    return left


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


def _fetch_bomq_builds(package: str, *, deadline: float | None = None) -> list[dict]:
    """Query bomq for all builds of a package."""
    base = get_settings().bomq_url.rstrip("/")
    params = urllib.parse.urlencode({"name": package, "strict": "true"})
    url = f"{base}{BOMQ_API_PATH}?{params}"
    with urllib.request.urlopen(url, timeout=_remaining(deadline)) as resp:
        data = json.loads(resp.read())
    if not isinstance(data, dict):
        raise TypeError(f"bomq returned {type(data).__name__}, expected object")
    builds = data.get("data", [])
    if not isinstance(builds, list):
        raise TypeError(f"bomq 'data' is {type(builds).__name__}, expected list")
    for i, entry in enumerate(builds):
        if not isinstance(entry, dict):
            raise TypeError(
                f"bomq 'data[{i}]' is {type(entry).__name__}, expected object"
            )
    return builds


def _resolve_build_id(
    session: koji.ClientSession,
    builds: list[dict],
    ps_update_stream: str,
    *,
    deadline: float | None = None,
) -> tuple[int, str] | None:
    """Find a build matching the stream and resolve it to a Koji build ID."""
    matches = [b for b in builds if b.get("stream_name") == ps_update_stream]
    if not matches:
        return None
    nvr = matches[0]["build_nvr"]
    session.opts["timeout"] = _remaining(deadline)
    build = session.getBuild(nvr)
    if not build:
        return None
    return build["id"], nvr


def _resolve_build_from_stream(
    session: koji.ClientSession,
    package: str,
    ps_update_stream: str,
    *,
    deadline: float | None = None,
) -> tuple[int, str] | None:
    """Query bomq for a build NVR, then resolve it to a Koji build ID.

    Returns (build_id, build_nvr) or None if no matching build is found.
    """
    builds = _fetch_bomq_builds(package, deadline=deadline)
    return _resolve_build_id(session, builds, ps_update_stream, deadline=deadline)


def _list_binary_rpms(
    session: koji.ClientSession, build_id: int, *, deadline: float | None = None
) -> list[str]:
    """List binary RPM names for a build, excluding source RPMs and noise."""
    session.opts["timeout"] = _remaining(deadline)
    rpms = session.listRPMs(buildID=build_id)
    return sorted(
        {
            r["name"]
            for r in rpms
            if r["arch"] != "src" and not _EXCLUDED_RPM_PATTERNS.search(r["name"])
        }
    )


def _resolve_stream(
    session: koji.ClientSession,
    package: str,
    builds: list[dict],
    ps_update_stream: str,
    *,
    deadline: float | None = None,
) -> ListBinaryRPMsOutput:
    """Resolve one stream from pre-fetched bomq builds."""
    try:
        resolved = _resolve_build_id(
            session, builds, ps_update_stream, deadline=deadline
        )
    except koji.GenericError as e:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="error",
            error_message=f"Koji/Brew error: {e}",
        )

    if resolved is None:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=ps_update_stream,
            status="not_found",
            error_message=(
                f"No builds found for package '{package}' "
                f"in stream '{ps_update_stream}'"
            ),
        )

    build_id, build_nvr = resolved

    try:
        binary_rpms = _list_binary_rpms(session, build_id, deadline=deadline)
    except (koji.GenericError, KeyError, TypeError) as e:
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


def _lookup_binary_rpms(
    package: str, ps_update_stream: str, *, deadline: float | None = None
) -> ListBinaryRPMsOutput:
    """Synchronous lookup of binary RPMs for a single (package, stream) pair."""
    with _brew_sem:
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
            builds = _fetch_bomq_builds(package, deadline=deadline)
        except urllib.error.HTTPError as e:
            return ListBinaryRPMsOutput(
                package=package,
                ps_update_stream=ps_update_stream,
                status="error",
                error_message=f"bomq API error: {e.code} {e.reason}",
            )
        except urllib.error.URLError as e:
            return ListBinaryRPMsOutput(
                package=package,
                ps_update_stream=ps_update_stream,
                status="error",
                error_message=f"bomq API error: {e.reason}",
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            return ListBinaryRPMsOutput(
                package=package,
                ps_update_stream=ps_update_stream,
                status="error",
                error_message=f"bomq response error: {e}",
            )
        except TimeoutError:
            return ListBinaryRPMsOutput(
                package=package,
                ps_update_stream=ps_update_stream,
                status="error",
                error_message="build system lookup deadline exceeded",
            )

        try:
            return _resolve_stream(
                session, package, builds, ps_update_stream, deadline=deadline
            )
        except TimeoutError:
            return ListBinaryRPMsOutput(
                package=package,
                ps_update_stream=ps_update_stream,
                status="error",
                error_message="build system lookup deadline exceeded",
            )


def _lookup_binary_rpms_batch(
    package: str, streams: list[str], *, deadline: float | None = None
) -> list[ListBinaryRPMsOutput]:
    """Batch lookup: one bomq request per package, one Brew session.

    Acquires the Brew semaphore once for the entire batch so that a
    single package with many streams does not hold multiple slots.
    """
    if deadline is None:
        deadline = time.monotonic() + ENRICHMENT_TIMEOUT_SECS

    def _timeout_result(stream: str) -> ListBinaryRPMsOutput:
        return ListBinaryRPMsOutput(
            package=package,
            ps_update_stream=stream,
            status="error",
            error_message="build system lookup deadline exceeded",
        )

    with _brew_sem:
        try:
            session = _create_brew_session()
        except koji.ConfigurationError as e:
            return [
                ListBinaryRPMsOutput(
                    package=package,
                    ps_update_stream=s,
                    status="error",
                    error_message=f"Koji profile '{BREW_PROFILE}' not configured: {e}",
                )
                for s in streams
            ]

        try:
            builds = _fetch_bomq_builds(package, deadline=deadline)
        except urllib.error.HTTPError as e:
            return [
                ListBinaryRPMsOutput(
                    package=package,
                    ps_update_stream=s,
                    status="error",
                    error_message=f"bomq API error: {e.code} {e.reason}",
                )
                for s in streams
            ]
        except urllib.error.URLError as e:
            return [
                ListBinaryRPMsOutput(
                    package=package,
                    ps_update_stream=s,
                    status="error",
                    error_message=f"bomq API error: {e.reason}",
                )
                for s in streams
            ]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            return [
                ListBinaryRPMsOutput(
                    package=package,
                    ps_update_stream=s,
                    status="error",
                    error_message=f"bomq response error: {e}",
                )
                for s in streams
            ]
        except TimeoutError:
            return [_timeout_result(s) for s in streams]

        results: list[ListBinaryRPMsOutput] = []
        for i, s in enumerate(streams):
            try:
                results.append(
                    _resolve_stream(session, package, builds, s, deadline=deadline)
                )
            except TimeoutError:
                results.extend(_timeout_result(s) for s in streams[i:])
                break
        return results


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
