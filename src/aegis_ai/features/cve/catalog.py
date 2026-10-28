"""bomq component-catalog reconciliation for SuggestAffectedComponents.

The HTTP GET lives with the builds lookup. This module turns catalog rows
into alias candidates and replaces a fallback ecosystem with a catalog type.
"""

import json
import logging
import re
import urllib.error
import urllib.request
from collections.abc import Callable

logger = logging.getLogger(__name__)

BOMQ_COMPONENTS_PATH = "/api/v0alpha/components"
# The components API caps each page at 100. Ask for the CLI's page size and
# follow total/count until the catalog for this name is exhausted.
_COMPONENT_PAGE_LIMIT = 1000
_SERVER_PAGE_CAP = 100
_MAX_COMPONENT_PAGES = 20
# A `{name}*` or `*{name}` glob wider than this is promiscuous: drop it.
_PROMISCUOUS_GLOB_LIMIT = 25
_TOKEN_STOPWORDS = frozenset({"lib", "org", "com"})
_MIN_TOKEN_LEN = 3
_MIN_GLOB_NAME_LEN = 4
# Types that must not replace a generic or unknown ecosystem.
# rpm/apk/deb stay generic so ACE still runs build-name search.
# oci stays generic too. Vulnerability reports are rarely about a container
# image itself. They are about content in the image, tracked as the packaged
# component (for example the nodejs RPM inside a Node.js container), not as
# the oci image.
# Allowlisted registries are left for the model to name.
# Types outside this set, including otp, replace a fallback.
_NON_REPLACING_TYPES = frozenset(
    {
        "cargo",
        "golang",
        "npm",
        "pypi",
        "maven",
        "gem",
        "generic",
        "unknown",
        "rpm",
        "apk",
        "deb",
        "oci",
    }
)
_FALLBACK_ECOSYSTEMS = frozenset({"generic", "unknown"})
_VERSION_PREFIX = re.compile(r"^(?:qt5|qt6|\d+)$", re.IGNORECASE)
_SUBPACKAGE_SUFFIXES = frozenset(
    {"devel", "libs", "debuginfo", "debugsource", "doc", "static", "perl", "minimal"}
)
# Engine/plugin suffixes are a different component from the parent name.
_ENGINE_SUFFIXES = frozenset({"pkcs11", "ibmca", "chil"})


def _component_row(entry: dict) -> dict | None:
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    comp_type = entry.get("type") if isinstance(entry.get("type"), str) else ""
    build_count = entry.get("build_count")
    if not isinstance(build_count, int):
        build_count = 0
    return {"name": name, "type": comp_type, "build_count": build_count}


def _fetch_bomq_components(base: str, name: str) -> list[dict]:
    """List catalog rows for ``name`` from one bomq host.

    Uses the components endpoint (``group_by=name``). ``exclude_types=""``
    disables the server's default RPM exclusion. Connection and JSON errors
    return an empty catalog so a down host does not fail the feature.
    A glob stops once it has more than ``_PROMISCUOUS_GLOB_LIMIT``
    case-insensitive names, because that result is discarded. Case variants
    count once, so a full page can stay under the limit and paging continues.
    """
    from aegis_ai.toolsets.tools.build_system import _bomq_get

    if not base or not base.strip() or not name:
        return []
    rows: list[dict] = []
    offset = 0
    try:
        for _ in range(_MAX_COMPONENT_PAGES):
            data = _bomq_get(
                base,
                BOMQ_COMPONENTS_PATH,
                {
                    "strict": "true",
                    "group_by": "name",
                    "name": name,
                    "exclude_dev": "true",
                    # Present, empty type filter: do not exclude RPM.
                    "exclude_types": '""',
                    "limit": str(_COMPONENT_PAGE_LIMIT),
                    "offset": str(offset),
                },
            )
            page = [_component_row(entry) for entry in data["data"]]
            page_rows = [row for row in page if row is not None]
            rows.extend(page_rows)
            # Keep the page that crosses the limit so the glob is discarded.
            # Stop there. A later page is wasted once the names are too wide.
            if (
                "*" in name
                and len({row["name"].lower() for row in rows}) > _PROMISCUOUS_GLOB_LIMIT
            ):
                break
            count = data.get("count")
            step = count if isinstance(count, int) and count > 0 else len(page_rows)
            if step <= 0:
                break
            offset += step
            total = data.get("total")
            if isinstance(total, int) and offset >= total:
                break
            if not isinstance(total, int) and len(page_rows) < _SERVER_PAGE_CAP:
                break
    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        TimeoutError,
        TypeError,
        ValueError,
        OSError,
    ) as exc:
        logger.warning(
            "bomq components lookup failed for %s on %s: %s", name, base, exc
        )
        return []
    return rows


def component_lookup_terms(name: str) -> list[tuple[str, str]]:
    """Exact names and globs to search for aliases of ``name``.

    Each item is ``("exact", term)`` or ``("glob", term)``.
    """
    terms: list[tuple[str, str]] = [("exact", name)]
    seen = {name.lower()}

    def add(kind: str, term: str) -> None:
        key = term.lower()
        if not term or key in seen:
            return
        seen.add(key)
        terms.append((kind, term))

    for token in re.split(r"[/_\-.]+", name):
        if len(token) < _MIN_TOKEN_LEN or token.lower() in _TOKEN_STOPWORDS:
            continue
        add("exact", token)
    if name.lower().startswith("lib") and len(name) > _MIN_TOKEN_LEN:
        add("exact", name[3:])
    stripped = re.sub(r"\d+$", "", name)
    if stripped != name:
        add("exact", stripped)
    if len(name) >= _MIN_GLOB_NAME_LEN:
        add("glob", f"{name}*")
        add("glob", f"*{name}")
    return terms


def _hyphen_parts(name: str) -> list[str]:
    return [part for part in name.split("-") if part]


def _is_subpackage(name: str) -> bool:
    parts = _hyphen_parts(name.split("/")[-1])
    return bool(parts) and parts[-1].lower() in _SUBPACKAGE_SUFFIXES


def _extra_suffix_ok(suffix: str) -> bool:
    key = suffix.lower()
    return key not in _SUBPACKAGE_SUFFIXES and key not in _ENGINE_SUFFIXES


def is_catalog_alias(suggested: str, catalog_name: str) -> bool:
    """True when ``catalog_name`` is a close alias of ``suggested``."""
    suggested_name = suggested.strip()
    catalog = catalog_name.strip()
    if (
        not suggested_name
        or not catalog
        or suggested_name.lower() == catalog.lower()
        or _is_subpackage(catalog)
        or _is_subpackage(suggested_name)
    ):
        return False
    if re.fullmatch(
        re.escape(suggested_name) + r"\d+", catalog, re.IGNORECASE
    ) or re.fullmatch(re.escape(catalog) + r"\d+", suggested_name, re.IGNORECASE):
        return True
    if (
        suggested_name.lower().startswith("lib")
        and catalog.lower() == suggested_name[3:].lower()
    ):
        return True
    if (
        catalog.lower().startswith("lib")
        and suggested_name.lower() == catalog[3:].lower()
    ):
        return True
    if "/" in catalog or "/" in suggested_name:
        return _one_extra_slash_segment(suggested_name, catalog)
    return _one_extra_hyphen_segment(suggested_name, catalog)


def _one_extra_slash_segment(suggested: str, catalog: str) -> bool:
    suggested_parts = suggested.split("/")
    catalog_parts = catalog.split("/")
    if (
        len(catalog_parts) == len(suggested_parts) + 1
        and catalog_parts[-1].lower() == suggested.lower()
    ):
        return True
    return (
        len(suggested_parts) == len(catalog_parts) + 1
        and suggested_parts[-1].lower() == catalog.lower()
    )


def _one_extra_hyphen_segment(suggested: str, catalog: str) -> bool:
    suggested_parts = _hyphen_parts(suggested)
    catalog_parts = _hyphen_parts(catalog)
    if (
        len(catalog_parts) == len(suggested_parts) + 1
        and "-".join(catalog_parts[1:]).lower() == suggested.lower()
        and _VERSION_PREFIX.fullmatch(catalog_parts[0])
    ):
        return True
    if (
        len(suggested_parts) == len(catalog_parts) + 1
        and "-".join(suggested_parts[1:]).lower() == catalog.lower()
        and _VERSION_PREFIX.fullmatch(suggested_parts[0])
    ):
        return True
    if (
        len(catalog_parts) == len(suggested_parts) + 1
        and "-".join(catalog_parts[:-1]).lower() == suggested.lower()
        and _extra_suffix_ok(catalog_parts[-1])
    ):
        return True
    return (
        len(suggested_parts) == len(catalog_parts) + 1
        and "-".join(suggested_parts[:-1]).lower() == catalog.lower()
        and _extra_suffix_ok(suggested_parts[-1])
    )


def catalog_alias_candidates(
    suggested: str, queries: list[tuple[str, list[dict]]]
) -> list[str]:
    """Names from catalog queries that are close aliases of ``suggested``.

    A glob with more than ``_PROMISCUOUS_GLOB_LIMIT`` distinct names is
    dropped. Exact-query hits are kept.
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        key = name.lower()
        if key in seen or key == suggested.lower():
            return
        if not is_catalog_alias(suggested, name):
            return
        seen.add(key)
        ordered.append(name)

    for kind, rows in queries:
        names = [row["name"] for row in rows if row.get("name")]
        distinct = {name.lower() for name in names}
        if kind == "glob" and len(distinct) > _PROMISCUOUS_GLOB_LIMIT:
            continue
        for name in names:
            add(name)
    return ordered


def reconcile_ecosystems(
    model_ecosystems: list[str], catalog_types: list[str]
) -> list[str]:
    """Replace fallback ecosystems using one component's catalog types.

    ``generic`` and ``unknown`` are fallbacks. A catalog type outside
    ``_NON_REPLACING_TYPES`` (for example ``otp``) replaces those
    fallbacks for this component. ``rpm``, ``apk``, ``deb``, and ``oci`` do not.
    Specific ecosystems the model already named are kept. When the model
    named only specific ecosystems, the list is left unchanged. A ``generic``
    row on this same component does not keep the fallback once a replacing
    type is present; that case is one component, not a second generic one.
    """
    named = [
        eco.strip() for eco in model_ecosystems if isinstance(eco, str) and eco.strip()
    ]
    specific: list[str] = []
    seen_specific: set[str] = set()
    has_fallback = False
    for eco in named:
        key = eco.lower()
        if key in _FALLBACK_ECOSYSTEMS:
            has_fallback = True
            continue
        if key not in seen_specific:
            seen_specific.add(key)
            specific.append(eco)

    outside: list[str] = []
    seen_outside: set[str] = set()
    for raw in catalog_types:
        if not isinstance(raw, str):
            continue
        key = raw.strip().lower()
        if not key or key in _NON_REPLACING_TYPES or key in seen_outside:
            continue
        seen_outside.add(key)
        outside.append(key)

    if not outside or (specific and not has_fallback):
        return list(model_ecosystems)
    if not has_fallback:
        return outside
    return specific + outside


def reconcile_ecosystems_by_component(
    model_ecosystems: list[str],
    catalog_types_by_component: list[list[str]],
) -> list[str]:
    """Union per-component results from ``reconcile_ecosystems``.

    Each inner list is the exact catalog types for one suggested component.
    A component whose types stay non-replacing keeps the model fallback.
    A component with a replacing type contributes that type instead.
    Components with no catalog rows do not put a replaced fallback back.
    """
    relevant = [types for types in catalog_types_by_component if types]
    if not relevant:
        return list(model_ecosystems)
    merged: list[str] = []
    seen: set[str] = set()
    for catalog_types in relevant:
        for eco in reconcile_ecosystems(model_ecosystems, catalog_types):
            if not isinstance(eco, str):
                continue
            text = eco.strip()
            key = text.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(text)
    return merged


def apply_bomq_aliases(
    components: list[str],
    candidates: list[tuple[str, str]],
    confirm: Callable[[str, str], bool],
) -> tuple[list[str], list[tuple[str, str]]]:
    """Append aliases ``confirm`` accepts, keeping the original name order."""
    updated = [name for name in components if isinstance(name, str)]
    seen = {name.lower() for name in updated}
    accepted: list[tuple[str, str]] = []
    for suggested, alias in candidates:
        if not isinstance(alias, str) or not alias.strip():
            continue
        key = alias.lower()
        if key in seen:
            continue
        if not confirm(suggested, alias):
            continue
        updated.append(alias)
        seen.add(key)
        accepted.append((suggested, alias))
    return updated, accepted
