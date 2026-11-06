"""Map flaw component seeds to same-project downstream names.

Catalog gathering is deterministic: bomq components queries with
``exclude_subcomponents`` (seed plus reference-caller module paths and
packaging tokens, narrowed when promiscuous), Anitya Fedora/EPEL names, then
build/RHCOS version samples. Soft labels mark likely keepers and drop hints.
Final keep/drop and affectedness may be refined by an agent;
``collect_downstream`` applies the soft-label rules deterministically for
tests and fallbacks.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from aegis_ai import get_settings
from aegis_ai.kernel_classifier import is_kernel_component

logger = logging.getLogger(__name__)

_USER_AGENT = "aegis-ai"
_TIMEOUT_SECS = 30
# Cap wall-clock time for the whole catalog prefetch so a slow bomq/Anitya
# host cannot stall sequential suggestion processing for one flaw.
_PREFETCH_TIMEOUT_SECS = 60
_PAGE_LIMIT = 100
_MAX_PAGES = 5
_PROMISCUOUS_NAME_THRESHOLD = 50
# Importer-only catalog names at or above this build count are omitted from
# _downstream (OSIM slows down with thousands of affects). Below the limit they
# stay as NOTAFFECTED with an explanation.
IMPORTER_AFFECT_LIMIT = 100

_LEGAL_ECOSYSTEMS = ("golang", "maven", "npm", "pypi", "cargo", "gem", "generic")
_REGISTRY_BACKENDS = ("crates.io", "pypi", "rubygems", "cpan", "npm", "maven")
_PACKAGING_PREFIXES = {"mingw", "mingw64", "cross"}
_LANGUAGE_PREFIXES = {
    "rust",
    "golang",
    "python",
    "python2",
    "python3",
    "nodejs",
    "rubygem",
    "perl",
}
_SUBPACKAGE_SUFFIXES = (
    "modules-extra",
    "debugsource",
    "debuginfo",
    "minimal",
    "static",
    "devel",
    "libs",
    "perl",
    "base",
    "core",
    "doc",
)
_ADVISORY_FIELDS = (
    "comment_zero",
    "description",
    "cve_description",
    "statement",
    "title",
)
_THROUGH_RE = re.compile(
    r"\b(?:from\s+)?v?([0-9][0-9A-Za-z.+]*)\s+through\s+v?([0-9][0-9A-Za-z.+]*)",
    re.IGNORECASE,
)
_BARE_THROUGH_RE = re.compile(
    r"\bthrough\s+v?([0-9][0-9A-Za-z.+]*)\b",
    re.IGNORECASE,
)
_GTE_RE = re.compile(r"(?:>=|≥)\s*v?([0-9][0-9A-Za-z.+]*)")
_LT_RE = re.compile(
    r"(?:before|fixed in|patched in|<)\s*v?([0-9][0-9A-Za-z.+]*)",
    re.IGNORECASE,
)
_VERSION_PART_RE = re.compile(r"\d+|[A-Za-z]+")
_KEEP_LABELS = frozenset(
    {
        "seed",
        "compat",
        "version_package",
        "clear_rebuild",
        "fork_rebuild",
        "anitya",
    }
)
_OPENSHIFT_PRIV_PREFIX = "github.com/openshift-priv/"
_OPENSHIFT_PUBLIC_PREFIX = "github.com/openshift/"
# Soft-label packaging drops are hard-enforced after the agent. Usage-policy
# drop_hints with drop_reason=None (patched submodule / server build) stay.
_PACKAGING_DROP_REASONS = frozenset(
    {
        "subpackage",
        "language_binding",
        "neighbor_rebuild",
        "engine_or_plugin",
        "lookalike",
        "unrelated_to_seed",
    }
)
# Soft-label keeps that must survive even when the agent omits them. Seeds and
# rebuilds stay agent/usage-policy controlled so importer parents can drop.
_HARD_KEEP_LABELS = frozenset({"version_package", "compat"})


@dataclass(frozen=True)
class CatalogHit:
    name: str
    type: str
    build_count: int | None = None


@dataclass(frozen=True)
class VersionBound:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class DownstreamRow:
    name: str
    build_type: str | None = None
    ecosystem: str | None = None
    rhcos: str | None = None
    affectedness: str | None = None
    evidence: str | None = None


@dataclass
class DownstreamResult:
    rows: list[DownstreamRow] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class CandidateHit:
    """One catalog name with a soft keep/drop label for agent context."""

    name: str
    type: str
    soft_label: str
    seed: str | None = None
    drop_reason: str | None = None
    build_count: int | None = None


@dataclass
class DownstreamCandidates:
    """Pre-enriched catalog context for SuggestManifestComponentAndState."""

    seeds: list[str] = field(default_factory=list)
    candidates: list[CandidateHit] = field(default_factory=list)
    anitya_names: dict[str, str] = field(default_factory=dict)
    versions: dict[str, list[str]] = field(default_factory=dict)
    rhcos_versions: dict[str, list[str]] = field(default_factory=dict)
    tools_used: list[str] = field(default_factory=list)
    advisory_text: str = ""
    promiscuous_hosts: list[str] = field(default_factory=list)
    explanation: str = ""
    # True when configured bomq hosts were queried but every response failed.
    # Distinguished from a trustworthy empty catalog so callers do not overwrite
    # existing _downstream mappings with a false-empty suggestion.
    catalog_unavailable: bool = False

    def allowed_names(self) -> set[str]:
        """Casefolded catalog candidate names allowed in the final mapping."""
        return {hit.name.casefold() for hit in self.candidates}

    def build_counts(self) -> dict[str, int]:
        """Max bomq build_count per catalog name (casefolded)."""
        counts: dict[str, int] = {}
        for hit in self.candidates:
            if hit.build_count is None:
                continue
            folded = hit.name.casefold()
            current = counts.get(folded)
            if current is None or hit.build_count > current:
                counts[folded] = hit.build_count
        return counts

    def to_prompt_dict(self) -> dict[str, Any]:
        """Serialize prefetch state for the agent prompt context."""
        return {
            "seeds": self.seeds,
            "candidates": [asdict(hit) for hit in self.candidates],
            "anitya_names": self.anitya_names,
            "versions": self.versions,
            "rhcos_versions": self.rhcos_versions,
            "promiscuous_hosts": self.promiscuous_hosts,
            "advisory_text": self.advisory_text,
        }


def filter_bomq_response(url: str, payload: Any) -> Any:
    """Keep only bomq fields used by downstream catalog / version sampling.

    Mirrors OSV tool-level filtering so eval ``catalog_cache`` stores slim
    bodies. Non-dict payloads, unknown paths, and responses without a ``data``
    list are returned unchanged (error JSON and non-bomq hosts).
    """
    if not isinstance(payload, dict):
        return payload
    data = payload.get("data")
    if not isinstance(data, list):
        return payload

    path = urllib.parse.urlsplit(url).path.rstrip("/")

    if path.endswith("/api/v0alpha/components"):
        slim_data: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            row: dict[str, Any] = {}
            for key in ("name", "type", "build_count"):
                if key in item:
                    row[key] = item[key]
            slim_data.append(row)
        filtered: dict[str, Any] = {"data": slim_data}
        if "total" in payload:
            filtered["total"] = payload["total"]
        return filtered

    if path.endswith("/api/v0/search/builds"):
        slim_data = []
        for item in data:
            if not isinstance(item, dict):
                continue
            row = {}
            if "build_version" in item:
                row["build_version"] = item["build_version"]
            elif "version" in item:
                row["version"] = item["version"]
            slim_data.append(row)
        return {"data": slim_data}

    if path.endswith("/api/v0/search/components"):
        slim_data = []
        for item in data:
            if not isinstance(item, dict):
                continue
            row = {"sources": []}
            if "build_name" in item:
                row["build_name"] = item["build_name"]
            for source in item.get("sources") or []:
                if not isinstance(source, dict):
                    continue
                components: list[dict[str, Any]] = []
                for component in source.get("components") or []:
                    if not isinstance(component, dict):
                        continue
                    slim_component: dict[str, Any] = {}
                    for key in ("name", "type", "version"):
                        if key in component:
                            slim_component[key] = component[key]
                    components.append(slim_component)
                row["sources"].append({"components": components})
            slim_data.append(row)
        return {"data": slim_data}

    return payload


def filter_anitya_response(url: str, payload: Any) -> Any:
    """Keep only Anitya fields used by downstream Fedora package mapping.

    Mirrors :func:`filter_bomq_response` so eval ``catalog_cache`` stores slim
    bodies. Non-dict payloads, unknown paths, and responses without an
    ``items`` / ``packages`` list are returned unchanged.
    """
    if not isinstance(payload, dict):
        return payload

    path = urllib.parse.urlsplit(url).path.rstrip("/")

    if path.endswith("/api/v2/projects"):
        items = payload.get("items")
        if not isinstance(items, list):
            return payload
        slim_items: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            row: dict[str, Any] = {}
            for key in ("name", "id", "backend", "homepage", "ecosystem"):
                if key in item:
                    row[key] = item[key]
            slim_items.append(row)
        filtered: dict[str, Any] = {"items": slim_items}
        for key in ("total_items", "total"):
            if key in payload:
                filtered[key] = payload[key]
        return filtered

    if "/api/project/" in path:
        packages = payload.get("packages")
        if not isinstance(packages, list):
            return payload
        slim_packages: list[dict[str, Any]] = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            row = {}
            for key in ("distro", "package_name"):
                if key in package:
                    row[key] = package[key]
            slim_packages.append(row)
        return {"packages": slim_packages}

    return payload


def http_get_json(
    url: str,
    *,
    timeout: float = _TIMEOUT_SECS,
    deadline: float | None = None,
) -> Any:
    """GET a JSON document.

    Connection, HTTP, and decode failures return ``None``. Callers must treat
    ``None`` as a lookup failure, not as an empty JSON document — a real empty
    catalog response is ``{"data": [], ...}``.

    Bomq and Anitya responses are field-filtered via
    :func:`filter_bomq_response` and :func:`filter_anitya_response` so callers
    and eval caches keep only the fields downstream code reads.

    When ``deadline`` (``time.monotonic()``) is set, the body is read with
    ``read1`` so a slow host cannot hold the request past the remaining
    prefetch budget; each ``read1`` is still bounded by ``timeout``.
    """
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if deadline is None:
                payload = response.read()
            else:
                chunks: list[bytes] = []
                while True:
                    if time.monotonic() >= deadline:
                        logger.warning(
                            "downstream lookup deadline exceeded while reading %s",
                            url,
                        )
                        return None
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                payload = b"".join(chunks)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.warning("downstream lookup failed for %s: %s", url, exc)
        return None
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("downstream lookup returned non-JSON for %s: %s", url, exc)
        return None
    return filter_anitya_response(url, filter_bomq_response(url, parsed))


def collect_downstream_candidates(
    flaw: dict[str, Any],
    *,
    get_json: Callable[[str], Any] | None = None,
    bomq_url: str | None = None,
    bomq_community_url: str | None = None,
    anitya_url: str | None = None,
    prefetch_timeout_secs: float | None = None,
) -> DownstreamCandidates:
    """Gather wide catalog candidates, Anitya names, and version samples."""
    settings = get_settings()
    primary = settings.bomq_url if bomq_url is None else bomq_url
    community = (
        settings.bomq_community_url
        if bomq_community_url is None
        else bomq_community_url
    )
    anitya = settings.anitya_url if anitya_url is None else anitya_url
    seeds = _seeds(flaw)
    advisory = _advisory_text(flaw)
    if not seeds:
        return DownstreamCandidates(
            advisory_text=advisory,
            explanation=_empty_explanation(),
        )
    if is_kernel_component(seeds):
        return DownstreamCandidates(
            seeds=seeds,
            advisory_text=advisory,
            explanation=_kernel_explanation(),
        )

    hosts = _hosts(primary, community)
    bomq_ok = 0
    bomq_failed = 0
    budget = (
        _PREFETCH_TIMEOUT_SECS
        if prefetch_timeout_secs is None
        else prefetch_timeout_secs
    )
    deadline = time.monotonic() + budget
    deadline_hit = False

    def counted(url: str) -> Any:
        """Fetch with overall deadline; count only attempted bomq responses."""
        nonlocal bomq_ok, bomq_failed, deadline_hit
        if deadline_hit:
            return None
        left = deadline - time.monotonic()
        if left <= 0:
            deadline_hit = True
            logger.warning(
                "downstream prefetch deadline exceeded after %.1fs; "
                "skipping remaining catalog lookups",
                budget,
            )
            return None
        if get_json is None:
            result = http_get_json(
                url, timeout=min(_TIMEOUT_SECS, left), deadline=deadline
            )
        else:
            result = get_json(url)
        if any(url.startswith(host) for host in hosts):
            # Only a dict whose data value is a list counts as a successful
            # catalog response (including an empty data list).
            if isinstance(result, dict) and isinstance(result.get("data"), list):
                bomq_ok += 1
            else:
                bomq_failed += 1
                # Non-list / error JSON bodies are failures; treat like None
                # for callers that only check emptiness.
                if result is not None and not (
                    isinstance(result, dict) and isinstance(result.get("data"), list)
                ):
                    return None
        return result

    getter = _cached(counted)
    tools: list[str] = []
    catalog: dict[str, list[CatalogHit]] = {}
    promiscuous: list[str] = []
    catalog_names = _catalog_query_names(seeds, flaw)

    def remember(hits: list[CatalogHit]) -> None:
        for hit in hits:
            bucket = catalog.setdefault(hit.name.casefold(), [])
            for index, existing in enumerate(bucket):
                if existing.type == hit.type:
                    if (hit.build_count or 0) > (existing.build_count or 0):
                        bucket[index] = hit
                    break
            else:
                bucket.append(hit)

    if hosts:
        tools.append("bomq_components")
        for name in catalog_names:
            for host in hosts:
                hits, was_promiscuous = _catalog_for_seed(getter, host, name)
                remember(hits)
                if was_promiscuous and host not in promiscuous:
                    promiscuous.append(host)

    skipped = _short_seed_names(seeds)
    anitya_names = _anitya_package_names(
        getter, anitya, catalog_names, catalog, tools, skipped
    )
    for package_name in anitya_names:
        if package_name.casefold() in catalog:
            continue
        for host in hosts:
            remember(_component_rows(getter, host, package_name, glob=False))

    candidates = _label_candidates(
        catalog_names,
        catalog,
        anitya_names,
        skipped,
        seed_names=seeds,
    )
    # A host failure or deadline with no candidates is untrustworthy. Both
    # hosts returning {"data": []} stays a real empty catalog (bomq_ok > 0).
    catalog_unavailable = (
        bool(hosts) and not candidates and (bomq_failed > 0 or deadline_hit)
    )
    if catalog_unavailable:
        return DownstreamCandidates(
            seeds=seeds,
            tools_used=tools,
            advisory_text=advisory,
            catalog_unavailable=True,
            explanation=_catalog_unavailable_explanation(seeds),
        )

    rpm_names = [
        hit.name
        for hit in candidates
        if hit.soft_label in _KEEP_LABELS and hit.type == "rpm"
    ]
    ecosystem_hits = [
        hit
        for hit in candidates
        if hit.soft_label in _KEEP_LABELS and hit.type in _LEGAL_ECOSYSTEMS
    ]
    versions = _rpm_versions_for_names(getter, hosts, rpm_names, tools)
    for name, sampled in _ecosystem_versions_for_hits(
        getter, hosts, ecosystem_hits, tools
    ).items():
        existing = versions.setdefault(name, [])
        for version in sampled:
            if version not in existing:
                existing.append(version)
            if len(existing) >= 8:
                break
        versions[name] = existing[:8]
    rhcos_versions = _rhcos_versions_for_names(getter, hosts, rpm_names, tools)
    return DownstreamCandidates(
        seeds=seeds,
        candidates=candidates,
        anitya_names=anitya_names,
        versions=versions,
        rhcos_versions=rhcos_versions,
        tools_used=tools,
        advisory_text=advisory,
        promiscuous_hosts=promiscuous,
        explanation=_candidate_explanation(seeds, candidates, promiscuous),
    )


def collect_downstream(
    flaw: dict[str, Any],
    *,
    get_json: Callable[[str], Any] | None = None,
    bomq_url: str | None = None,
    bomq_community_url: str | None = None,
    anitya_url: str | None = None,
) -> DownstreamResult:
    """Return soft-label keepers for one flaw (deterministic baseline)."""
    gathered = collect_downstream_candidates(
        flaw,
        get_json=get_json,
        bomq_url=bomq_url,
        bomq_community_url=bomq_community_url,
        anitya_url=anitya_url,
    )
    if not gathered.seeds or not gathered.candidates:
        return DownstreamResult(
            tools_used=gathered.tools_used,
            explanation=gathered.explanation or _empty_explanation(),
        )
    rows = resolve_soft_label_rows(
        gathered.candidates,
        gathered.versions,
        gathered.rhcos_versions,
        gathered.seeds,
        flaw=flaw,
    )
    return DownstreamResult(
        rows=rows,
        tools_used=gathered.tools_used,
        explanation=_explanation(gathered.seeds, rows),
    )


def suppressed_short_path_names(
    seeds: list[str],
    candidate_names: set[str],
) -> set[str]:
    """Bare final segments to omit when a fuller seed path is a catalog hit.

    Includes short names that only appear as the final segment of another seed
    (scoped npm), plus the rclone case: when a module-path seed itself is in
    ``candidate_names``, suppress that path's final segment. When the path is
    absent from the catalog, Anitya may still supply a short RPM name (nuclei).
    """
    short = _short_seed_names(seeds)
    folded_candidates = {name.casefold() for name in candidate_names}
    for seed in seeds:
        if not _is_module_path(seed) or seed.casefold() not in folded_candidates:
            continue
        segment = seed.rsplit("/", 1)[-1].casefold()
        if segment:
            short.add(segment)
    return short


def resolve_soft_label_rows(
    candidates: list[CandidateHit],
    versions: dict[str, list[str]],
    rhcos_versions: dict[str, list[str]],
    seeds: list[str],
    *,
    flaw: dict[str, Any] | None = None,
) -> list[DownstreamRow]:
    """Keep soft-label keepers and attach affectedness / RHCOS companions."""
    planned: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    short_seeds = suppressed_short_path_names(seeds, {hit.name for hit in candidates})

    catalog_types: dict[str, list[CatalogHit]] = {}
    for hit in candidates:
        catalog_types.setdefault(hit.name.casefold(), []).append(
            CatalogHit(hit.name, hit.type, hit.build_count)
        )

    def add(name: str, kind: str, value: str, *, compat: bool) -> None:
        identity = (name.casefold(), kind, value)
        if identity in seen or name.casefold() in short_seeds:
            return
        seen.add(identity)
        planned.append({"name": name, "kind": kind, "value": value, "compat": compat})

    for hit in candidates:
        if hit.soft_label not in _KEEP_LABELS:
            continue
        if hit.name.casefold() in short_seeds:
            continue
        module_path = _is_module_path(hit.name)
        classified = _classify(catalog_types.get(hit.name.casefold(), []), module_path)
        if classified is None:
            continue
        kind, value = classified
        add(hit.name, kind, value, compat=hit.soft_label == "compat")

    return _rows_with_affectedness(
        planned,
        versions,
        rhcos_versions,
        flaw=flaw,
    )


def post_filter_manifest_entries(
    entries: list[Any],
    allowed_names: set[str],
) -> list[Any]:
    """Drop invented names; allow rhcos companions only for kept RPM names."""
    kept_rpm: set[str] = set()
    for entry in entries:
        name = getattr(entry, "name", None)
        if (
            isinstance(name, str)
            and name.casefold() in allowed_names
            and getattr(entry, "build_type", None) == "rpm"
        ):
            kept_rpm.add(name.casefold())
    filtered: list[Any] = []
    for entry in entries:
        name = getattr(entry, "name", None)
        if not isinstance(name, str):
            continue
        folded = name.casefold()
        rhcos = getattr(entry, "rhcos", None)
        if rhcos is not None:
            if folded in kept_rpm:
                filtered.append(entry)
            continue
        if folded not in allowed_names:
            continue
        filtered.append(entry)
    return filtered


def drop_suppressed_short_path_entries(
    entries: list[Any],
    suppressed: set[str],
) -> list[Any]:
    """Remove bare final-segment names suppressed for a catalog-hit module path."""
    if not suppressed:
        return entries
    kept: list[Any] = []
    for entry in entries:
        name = getattr(entry, "name", None)
        if isinstance(name, str) and name.casefold() in suppressed:
            continue
        kept.append(entry)
    return kept


_GITHUB_REPO_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


def reference_module_paths(flaw: dict[str, Any]) -> list[str]:
    """Go-style ``github.com/org/repo`` paths named in flaw reference URLs."""
    found: list[str] = []
    seen: set[str] = set()
    for ref in flaw.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if not isinstance(url, str):
            continue
        match = _GITHUB_REPO_RE.search(url)
        if match is None:
            continue
        path = f"github.com/{match.group(1)}/{match.group(2)}"
        folded = path.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        found.append(path)
    return found


def _related_to_seed(path: str, seeds: list[str]) -> bool:
    """True when ``path`` is a seed, or a parent or submodule of a seed."""
    folded = path.casefold().rstrip("/")
    for seed in seeds:
        seed_folded = str(seed or "").casefold().rstrip("/")
        if not seed_folded:
            continue
        if (
            folded == seed_folded
            or folded.startswith(seed_folded + "/")
            or seed_folded.startswith(folded + "/")
        ):
            return True
    return False


def promote_reference_caller_modules(
    entries: list[Any],
    flaw: dict[str, Any],
    seeds: list[str],
    confirm_name: Callable[[str], list[CatalogHit]] | None,
) -> tuple[list[Any], str]:
    """Replace a bare ecosystem shorthand with the caller module in references.

    Seed modules are left alone. Build-typed packaging names (RPM / container)
    stay; only a short ecosystem row is rewritten when the fuller path is a
    catalog hit.
    """
    if confirm_name is None or not entries:
        return entries, ""
    paths = [
        path
        for path in reference_module_paths(flaw)
        if not _related_to_seed(path, seeds)
    ]
    if not paths:
        return entries, ""

    by_fold: dict[str, Any] = {}
    order: list[str] = []
    for entry in entries:
        name = getattr(entry, "name", None)
        if not isinstance(name, str) or not name.strip():
            continue
        folded = name.casefold()
        if folded in by_fold:
            continue
        by_fold[folded] = entry
        order.append(folded)

    replacements: dict[str, Any] = {}
    notes: list[str] = []
    for path in paths:
        segment = path.rsplit("/", 1)[-1].casefold()
        if not segment or path.casefold() in by_fold or segment not in by_fold:
            continue
        short = by_fold[segment]
        if getattr(short, "build_type", None):
            continue
        hits = confirm_name(path)
        if not hits:
            continue
        entry = _manifest_entry_from_hits(path, hits, _default_manifest_entry)
        if entry is None:
            continue
        # Do not copy the short row's verdict: the module path is not
        # version-sampled by confirm_name, so leave UNKNOWN.
        replacements[segment] = entry
        notes.append(
            f"Replaced bare {getattr(short, 'name', segment)} with {entry.name} "
            "because flaw references name that module and the catalog confirms it."
        )

    if not replacements:
        return entries, ""

    promoted: list[Any] = []
    seen: set[str] = set()
    for folded in order:
        if folded in replacements:
            entry = replacements[folded]
            key = entry.name.casefold()
            if key in seen:
                continue
            promoted.append(entry)
            seen.add(key)
            continue
        promoted.append(by_fold[folded])
        seen.add(folded)
    return promoted, " ".join(notes)


def drop_short_segments_of_kept_modules(entries: list[Any]) -> list[Any]:
    """Drop a bare ecosystem shorthand when that module path is also kept.

    Build-typed packaging (RPM / container) with the same final token stays.
    """
    module_segments = {
        entry.name.rsplit("/", 1)[-1].casefold()
        for entry in entries
        if isinstance(getattr(entry, "name", None), str) and "/" in entry.name
    }
    if not module_segments:
        return entries
    return [
        entry
        for entry in entries
        if not (
            isinstance(getattr(entry, "name", None), str)
            and "/" not in entry.name
            and entry.name.casefold() in module_segments
            and getattr(entry, "build_type", None) is None
        )
    ]


def rejected_soft_label_names(candidates: list[CandidateHit]) -> set[str]:
    """Casefolded names that soft-label packaging rules hard-reject.

    A name is rejected when it has a drop_hint with a packaging ``drop_reason``
    and no keep-label hit. Usage-policy drop_hints with ``drop_reason=None``
    are not rejected.
    """
    keep: set[str] = set()
    reject: set[str] = set()
    for hit in candidates:
        folded = hit.name.casefold()
        if hit.soft_label in _KEEP_LABELS:
            keep.add(folded)
            continue
        if hit.soft_label == "drop_hint" and hit.drop_reason in _PACKAGING_DROP_REASONS:
            reject.add(folded)
    return reject - keep


def drop_soft_label_rejects(
    entries: list[Any],
    candidates: list[CandidateHit],
) -> list[Any]:
    """Remove entries soft-labeled as packaging rejects (plugins, lookalikes)."""
    rejected = rejected_soft_label_names(candidates)
    if not rejected:
        return entries
    kept: list[Any] = []
    for entry in entries:
        name = getattr(entry, "name", None)
        if isinstance(name, str) and name.casefold() in rejected:
            continue
        kept.append(entry)
    return kept


def ensure_soft_label_keeps(
    entries: list[Any],
    baseline_rows: list[DownstreamRow],
    candidates: list[CandidateHit],
) -> list[Any]:
    """Re-add version_package / compat baseline rows the agent omitted.

    Mirrors ``drop_soft_label_rejects`` for deterministic keeps. Does not
    restore ``seed`` or rebuild labels — usage policy remains authoritative
    for those.
    """
    hard_keep: set[str] = set()
    display: dict[str, str] = {}
    for hit in candidates:
        if hit.soft_label not in _HARD_KEEP_LABELS:
            continue
        folded = hit.name.casefold()
        hard_keep.add(folded)
        display.setdefault(folded, hit.name)
    if not hard_keep:
        return entries

    present: set[str] = set()
    for entry in entries:
        name = getattr(entry, "name", None)
        if isinstance(name, str) and name.strip():
            present.add(name.casefold())

    restored: list[Any] = []
    seen_restore: set[str] = set()
    for row in baseline_rows:
        if row.rhcos and not row.build_type and not row.ecosystem:
            continue
        folded = row.name.casefold()
        if folded not in hard_keep or folded in present or folded in seen_restore:
            continue
        seen_restore.add(folded)
        restored.append(
            _default_manifest_entry(
                name=display.get(folded, row.name),
                build_type=row.build_type,
                ecosystem=row.ecosystem,
                rhcos=None,
                affectedness=row.affectedness,
                evidence=row.evidence,
            )
        )
    if not restored:
        return entries
    return list(entries) + restored


def align_manifest_search_keys(
    entries: list[Any],
    baseline_rows: list[DownstreamRow],
) -> list[Any]:
    """Prefer soft-label build_type/ecosystem when the LLM swaps them.

    ``maven`` and ``generic`` are legal on both fields. Soft-label marks
    bundled registry coordinates as ``ecosystem`` and exact builds as
    ``build_type``. Restore that key for names still present in the baseline
    so ACE searches the right bomq kind. Also copy sample-based AFFECTED /
    NOTAFFECTED when the agent left UNKNOWN or blank.
    """
    by_name: dict[str, DownstreamRow] = {}
    for row in baseline_rows:
        if row.rhcos and not row.build_type and not row.ecosystem:
            continue
        folded = row.name.casefold()
        existing = by_name.get(folded)
        if existing is None or (
            existing.rhcos and not existing.build_type and not existing.ecosystem
        ):
            by_name[folded] = row

    for entry in entries:
        if (
            getattr(entry, "rhcos", None) is not None
            and not getattr(entry, "build_type", None)
            and not getattr(entry, "ecosystem", None)
        ):
            continue
        name = getattr(entry, "name", None)
        if not isinstance(name, str):
            continue
        baseline = by_name.get(name.casefold())
        if baseline is None:
            continue
        if baseline.ecosystem:
            entry.build_type = None
            entry.ecosystem = baseline.ecosystem
        elif baseline.build_type:
            entry.ecosystem = None
            entry.build_type = baseline.build_type
        baseline_affect = getattr(baseline, "affectedness", None)
        entry_affect = getattr(entry, "affectedness", None)
        if baseline_affect in {"AFFECTED", "NOTAFFECTED"} and entry_affect in (
            None,
            "",
            "UNKNOWN",
        ):
            entry.affectedness = baseline_affect
            if getattr(entry, "evidence", None) in (None, "") and baseline.evidence:
                entry.evidence = baseline.evidence
    return entries


def _catalog_for_seed(
    getter: Callable[[str], Any],
    host: str,
    seed: str,
) -> tuple[list[CatalogHit], bool]:
    """Wide ``*{seed}*`` then narrower globs when the host is promiscuous."""
    exact = _component_rows(getter, host, seed, glob=False)
    wide = _component_rows(getter, host, f"*{seed}*", glob=True)
    distinct = {hit.name.casefold() for hit in wide}
    if len(distinct) <= _PROMISCUOUS_NAME_THRESHOLD:
        return _merge_hits(exact, wide), False

    narrow = _merge_hits(
        exact,
        _component_rows(getter, host, f"*{seed}", glob=True),
        _component_rows(getter, host, f"{seed}*", glob=True),
        _component_rows(getter, host, f"compat-{seed}*", glob=True),
    )
    return narrow, True


def _merge_hits(*groups: list[CatalogHit]) -> list[CatalogHit]:
    """Deduplicate catalog hits by name/type, keeping the highest build_count."""
    found: dict[tuple[str, str], CatalogHit] = {}
    for group in groups:
        for hit in group:
            key = (hit.name.casefold(), hit.type)
            existing = found.get(key)
            if existing is None or (hit.build_count or 0) > (existing.build_count or 0):
                found[key] = hit
    return list(found.values())


def _label_candidates(
    seeds: list[str],
    catalog: dict[str, list[CatalogHit]],
    anitya_names: dict[str, str],
    skipped: set[str],
    *,
    seed_names: list[str] | None = None,
) -> list[CandidateHit]:
    """Label catalog hits.

    ``seeds`` is the query-name list (flaw components plus reference tokens).
    ``seed_names`` is the flaw ``components`` list only; exact hits of those
    names get the ``seed`` keeper label. Exact hits of reference-only query
    names get ``reference`` (visible to the agent, not a soft-label keeper).
    Structural rebuilds against reference tokens still use
    ``version_package`` / ``fork_rebuild`` / ``clear_rebuild``.
    """
    labeled: list[CandidateHit] = []
    seen: set[tuple[str, str]] = set()
    flaw_seeds = seed_names if seed_names is not None else seeds
    flaw_folded = {name.casefold() for name in flaw_seeds}

    def add(hit: CatalogHit, label: str, seed: str | None, reason: str | None) -> None:
        key = (hit.name.casefold(), hit.type)
        if key in seen:
            return
        seen.add(key)
        labeled.append(
            CandidateHit(
                name=hit.name,
                type=hit.type,
                soft_label=label,
                seed=seed,
                drop_reason=reason,
                build_count=hit.build_count,
            )
        )

    for seed in flaw_seeds:
        if seed.casefold() in skipped:
            continue
        for hit in catalog.get(seed.casefold(), []):
            add(hit, "seed", seed, None)

    # Exact hits of reference-derived query names: visible, not keepers.
    for query_name in seeds:
        folded = query_name.casefold()
        if folded in flaw_folded or folded in skipped:
            continue
        for hit in catalog.get(folded, []):
            add(hit, "reference", query_name, None)

    for package_name, seed in anitya_names.items():
        if _is_subpackage(package_name):
            continue
        for hit in catalog.get(package_name.casefold(), []):
            if package_name.casefold() == seed.casefold():
                continue
            add(hit, "anitya", seed, None)

    # Structural rebuilds may match against flaw seeds or reference tokens.
    label_anchors = list(dict.fromkeys([*flaw_seeds, *seeds]))
    for hits in catalog.values():
        for hit in hits:
            if (hit.name.casefold(), hit.type) in seen:
                continue
            seed = _best_seed_for_name(hit.name, label_anchors, skipped)
            if seed is None:
                add(hit, "drop_hint", None, "unrelated_to_seed")
                continue
            label, reason = _soft_label_for(hit, seed)
            # Exact name match against a reference token is already labeled
            # above; _soft_label_for would call it "seed" — skip that path.
            if label == "seed" and seed.casefold() not in flaw_folded:
                add(hit, "reference", seed, None)
                continue
            add(hit, label, seed, reason)
    return labeled


def _best_seed_for_name(name: str, seeds: list[str], skipped: set[str]) -> str | None:
    """Return the seed that best explains a catalog name, or None if unrelated."""
    folded = name.casefold()
    for seed in seeds:
        if seed.casefold() in skipped:
            continue
        seed_folded = seed.casefold()
        if folded == seed_folded:
            return seed
        if _is_openshift_fork_rebuild(name, seed):
            return seed
        if _is_module_path(seed):
            continue
        if (
            _is_compat(name, seed)
            or _is_version_package(name, seed)
            or folded.endswith("-" + seed_folded)
            or folded.startswith(seed_folded)
        ):
            return seed
    return None


def _soft_label_for(hit: CatalogHit, seed: str) -> tuple[str, str | None]:
    """Assign a soft keep/drop label for a catalog hit relative to one seed."""
    name = hit.name
    if name.casefold() == seed.casefold():
        return ("seed", None)
    if _is_subpackage(name):
        return ("drop_hint", "subpackage")
    if _is_compat(name, seed):
        return ("compat", None)
    if _is_version_package(name, seed):
        return ("version_package", None)
    if _is_openshift_fork_rebuild(name, seed):
        return ("fork_rebuild", None)
    if hit.type == "rpm" and _is_clear_rebuild(name, seed):
        return ("clear_rebuild", None)
    if hit.type == "rpm" and _is_language_binding(name, seed):
        return ("drop_hint", "language_binding")
    if hit.type == "rpm" and name.casefold().endswith("-" + seed.casefold()):
        return ("drop_hint", "neighbor_rebuild")
    if name.casefold().startswith(seed.casefold() + "-"):
        return ("drop_hint", "engine_or_plugin")
    return ("drop_hint", "lookalike")


def _canonical_openshift_path(name: str) -> str | None:
    """Map ``github.com/openshift-priv/<project>/…`` to the public openshift org."""
    folded = name.casefold().rstrip("/")
    if not folded.startswith(_OPENSHIFT_PRIV_PREFIX):
        return None
    rest = folded[len(_OPENSHIFT_PRIV_PREFIX) :]
    if not rest:
        return None
    return _OPENSHIFT_PUBLIC_PREFIX + rest


def _github_repo_segment(path: str) -> str | None:
    """Repo name for ``github.com/org/repo[/…]``, or a bare non-path name."""
    folded = path.casefold().rstrip("/")
    if folded.startswith("github.com/"):
        parts = folded.split("/")
        if len(parts) >= 3 and parts[2]:
            return parts[2]
        return None
    if "/" in folded or not folded:
        return None
    return folded


def _is_openshift_fork_rebuild(name: str, seed: str) -> bool:
    """True when ``name`` is an openshift-priv path for the seed's GitHub repo."""
    canonical = _canonical_openshift_path(name)
    if canonical is None:
        return False
    parts = canonical.split("/")
    if len(parts) < 3 or not parts[2]:
        return False
    project = parts[2]
    seed_repo = _github_repo_segment(seed)
    return seed_repo is not None and project == seed_repo


def _is_clear_rebuild(name: str, seed: str) -> bool:
    """Final-token rebuild with a digit-bearing or packaging prefix."""
    if "-" not in name:
        return False
    prefix, final = name.rsplit("-", 1)
    if final.casefold() != seed.casefold():
        return False
    if _is_language_binding(name, seed):
        return False
    parts = prefix.split("-")
    first = parts[0].casefold()
    if first in _PACKAGING_PREFIXES:
        return True
    last_prefix = parts[-1]
    return bool(last_prefix) and last_prefix[-1].isdigit()


def _is_language_binding(name: str, seed: str) -> bool:
    """True when the RPM name is a language-binding prefix of the seed."""
    if "-" not in name:
        return False
    first = name.split("-", 1)[0].casefold()
    return first in _LANGUAGE_PREFIXES


def _is_version_package(name: str, seed: str) -> bool:
    """True for same-project version packaging (libsoup3, zabbix6.0, OpenImageIO2.5)."""
    folded = name.casefold()
    seed_folded = seed.casefold()
    if folded == seed_folded:
        return False
    # Major may be dotted (Fedora zabbix6.0 / OpenImageIO2.5), not only bare digits.
    version_suffix = r"\d+(?:\.\d+)*"
    if re.fullmatch(rf"{re.escape(seed_folded)}{version_suffix}", folded):
        return True
    return (
        re.fullmatch(rf"{re.escape(seed_folded)}-{version_suffix}", folded) is not None
    )


def _seeds(flaw: dict[str, Any]) -> list[str]:
    """Extract unique non-empty component seed names from a flaw body."""
    raw = flaw.get("components") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    seeds: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip() and item not in seeds:
            seeds.append(item.strip())
    return seeds


def _advisory_text(flaw: dict[str, Any]) -> str:
    """Join advisory text fields used for version-bound parsing."""
    return " ".join(str(flaw.get(key) or "") for key in _ADVISORY_FIELDS)


def _cached(getter: Callable[[str], Any]) -> Callable[[str], Any]:
    """Wrap a URL getter with a per-URL response cache."""
    cache: dict[str, Any] = {}

    def cached(url: str) -> Any:
        if url not in cache:
            cache[url] = getter(url)
        return cache[url]

    return cached


def _hosts(primary: str, community: str) -> list[str]:
    """Return unique non-empty bomq hosts with trailing slashes stripped."""
    hosts: list[str] = []
    for host in (primary, community):
        normalized = (host or "").rstrip("/")
        if normalized and normalized not in hosts:
            hosts.append(normalized)
    return hosts


def _catalog_query_names(seeds: list[str], flaw: dict[str, Any]) -> list[str]:
    """Flaw seeds plus reference caller modules and their packaging tokens.

    A seed such as ``github.com/prometheus/common`` does not catalog the
    Prometheus server module, openshift-priv rebuild, or ``prometheus`` RPMs.
    Reference URLs that name ``github.com/prometheus/prometheus`` add that
    path and the ``prometheus`` token so those candidates are gathered first.
    """
    names: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        folded = name.casefold().strip()
        if not folded or folded in seen:
            return
        seen.add(folded)
        names.append(name.strip())

    for seed in seeds:
        add(seed)
    for path in reference_module_paths(flaw):
        if _related_to_seed(path, seeds):
            continue
        add(path)
        repo = _github_repo_segment(path)
        if repo:
            add(repo)
    return names


def _component_rows(
    getter: Callable[[str], Any],
    host: str,
    name: str,
    *,
    glob: bool,
) -> list[CatalogHit]:
    """Page bomq component search results into CatalogHit rows."""
    hits: list[CatalogHit] = []
    for page in range(1, _MAX_PAGES + 1):
        query = {
            "name": name,
            "strict": "false" if glob else "true",
            "group_by": "name",
            "exclude_dev": "true",
            "exclude_subcomponents": "true",
            "exclude_types": "",
            "limit": str(_PAGE_LIMIT),
            "page": str(page),
        }
        url = f"{host}/api/v0alpha/components?{urllib.parse.urlencode(query)}"
        payload = getter(url)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if not isinstance(item, dict):
                continue
            item_name = item.get("name")
            item_type = item.get("type")
            if not isinstance(item_name, str) or not isinstance(item_type, str):
                continue
            raw_count = item.get("build_count")
            build_count = raw_count if isinstance(raw_count, int) else None
            hits.append(CatalogHit(item_name, item_type.casefold(), build_count))
        total = payload.get("total") if isinstance(payload, dict) else None
        if isinstance(total, int) and page * _PAGE_LIMIT >= total:
            break
        if len(data) < _PAGE_LIMIT:
            break
    if glob:
        hits = [hit for hit in hits if _glob_match(name, hit.name)]
    return hits


def _glob_match(pattern: str, name: str) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(regex, name, flags=re.IGNORECASE) is not None


def _anitya_package_names(
    getter: Callable[[str], Any],
    anitya: str,
    seeds: list[str],
    catalog: dict[str, list[CatalogHit]],
    tools: list[str],
    skipped: set[str],
) -> dict[str, str]:
    """Map a confirmed Fedora package name back to the seed that found it."""
    base = (anitya or "").rstrip("/")
    if not base:
        return {}
    found: dict[str, str] = {}
    queried = False
    for seed in seeds:
        if seed.casefold() in skipped:
            continue
        if _is_module_path(seed) and catalog.get(seed.casefold()):
            continue
        if not queried:
            tools.append("anitya_projects")
            queried = True
        query = seed
        module_path = _is_module_path(seed)
        if module_path:
            segment = _anitya_segment(seed)
            if not segment:
                continue
            query = segment
        projects = _anitya_projects(getter, base, query)
        if module_path:
            projects = [item for item in projects if _homepage_has_seed(item, seed)]
        preferred = _prefer_non_registry(projects)
        if not _remember_packages(getter, base, preferred, seed, found):
            preferred_ids = {project.get("id") for project in preferred}
            others = [
                project
                for project in projects
                if project.get("id") not in preferred_ids
            ]
            _remember_packages(getter, base, others, seed, found)
    return found


def _remember_packages(
    getter: Callable[[str], Any],
    base: str,
    projects: list[dict[str, Any]],
    seed: str,
    found: dict[str, str],
) -> bool:
    """Record Fedora package names from Anitya projects into ``found``."""
    before = len(found)
    for project in projects:
        backend = str(project.get("backend") or "")
        for package_name in _fedora_packages(getter, base, project.get("id")):
            if _is_subpackage(package_name):
                continue
            if not _language_prefix_allowed(package_name, backend):
                continue
            found.setdefault(package_name, seed)
    return len(found) > before


def _anitya_projects(
    getter: Callable[[str], Any], base: str, name: str
) -> list[dict[str, Any]]:
    """Page Anitya projects whose name exactly matches the query."""
    projects: list[dict[str, Any]] = []
    for page in range(1, _MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {"name": name, "page": page, "items_per_page": _PAGE_LIMIT}
        )
        payload = getter(f"{base}/api/v2/projects/?{query}")
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if not isinstance(item, dict):
                continue
            item_name = item.get("name")
            if isinstance(item_name, str) and item_name.casefold() == name.casefold():
                projects.append(item)
        total = None
        if isinstance(payload, dict):
            total = payload.get("total_items", payload.get("total"))
        if isinstance(total, int) and page * _PAGE_LIMIT >= total:
            break
        if len(items) < _PAGE_LIMIT:
            break
    return projects


def _fedora_packages(
    getter: Callable[[str], Any], base: str, project_id: Any
) -> list[str]:
    """List Fedora/EPEL package names for one Anitya project id."""
    if isinstance(project_id, str) and project_id.isdigit():
        project_id = int(project_id)
    if not isinstance(project_id, int) or isinstance(project_id, bool):
        return []
    payload = getter(f"{base}/api/project/{project_id}")
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(packages, list):
        return []
    names: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        distro = str(package.get("distro") or "").casefold()
        package_name = package.get("package_name")
        if (
            distro in {"fedora", "fedora epel"}
            and isinstance(package_name, str)
            and package_name not in names
        ):
            names.append(package_name)
    return names


def _prefer_non_registry(projects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer Anitya projects whose backend is not a language registry."""
    non_registry = [
        project
        for project in projects
        if not any(
            token in str(project.get("backend") or "").casefold()
            for token in _REGISTRY_BACKENDS
        )
    ]
    return non_registry or projects


def _homepage_has_seed(project: dict[str, Any], seed: str) -> bool:
    """True when the Anitya homepage/ecosystem blob contains the seed path."""
    blob = f"{project.get('homepage') or ''} {project.get('ecosystem') or ''}"
    blob = blob.casefold()
    needle = seed.casefold()
    if needle in blob:
        return True
    stripped = re.sub(r"/v\d+$", "", needle)
    return stripped != needle and stripped in blob


def _anitya_segment(seed: str) -> str | None:
    """Final path segment used to query Anitya for a module-path seed."""
    parts = [part for part in seed.split("/") if part]
    if not parts:
        return None
    if parts[-1].startswith("@") or re.fullmatch(r"v\d+", parts[-1]):
        if len(parts) < 2:
            return None
        segment = parts[-2]
    else:
        segment = parts[-1]
    if len(segment) < 3:
        return None
    return segment


def _is_module_path(name: str) -> bool:
    """True for Go/npm-style module paths (slash or scoped ``@`` name)."""
    return "/" in name or name.startswith("@")


def _is_subpackage(name: str) -> bool:
    """True when the name ends with a known RPM subpackage suffix."""
    folded = name.casefold()
    return any(folded.endswith("-" + suffix) for suffix in _SUBPACKAGE_SUFFIXES)


def _language_prefix_allowed(name: str, backend: str) -> bool:
    """Allow language-prefixed Fedora names only for matching Anitya backends."""
    token = name.split("-", 1)[0].casefold()
    expected = {
        "rust": ("crates.io", "cargo"),
        "golang": ("golang",),
        "python": ("pypi",),
        "python2": ("pypi",),
        "python3": ("pypi",),
        "nodejs": ("npm",),
        "rubygem": ("rubygems", "gem"),
        "perl": ("cpan", "perl"),
    }.get(token)
    if expected is None:
        return True
    folded = backend.casefold()
    return any(item in folded for item in expected)


def _short_seed_names(seeds: list[str]) -> set[str]:
    """Bare names that are only the final segment of another seed."""
    found: set[str] = set()
    for seed in seeds:
        folded = seed.casefold()
        for other in seeds:
            if other == seed:
                continue
            other_folded = other.casefold()
            if other_folded.endswith(("/" + folded, "@" + folded)):
                found.add(folded)
    return found


def _classify(hits: list[CatalogHit], module_path: bool) -> tuple[str, str] | None:
    """Pick build_type or ecosystem search key for a set of catalog hits."""
    types = {hit.type for hit in hits}
    if module_path:
        ecosystem = _best_ecosystem(types)
        if ecosystem:
            return ("ecosystem", ecosystem)
        if "rpm" in types:
            return ("build_type", "rpm")
        return None
    if "rpm" in types:
        return ("build_type", "rpm")
    ecosystem = _best_ecosystem(types)
    if ecosystem:
        return ("ecosystem", ecosystem)
    return None


def _best_ecosystem(types: set[str]) -> str | None:
    """Choose the preferred legal ecosystem from catalog hit types."""
    for ecosystem in _LEGAL_ECOSYSTEMS:
        if ecosystem in types and ecosystem != "generic":
            return ecosystem
    if "generic" in types:
        return "generic"
    return None


def _is_compat(name: str, seed: str) -> bool:
    return (
        re.fullmatch(
            rf"compat-{re.escape(seed)}\d+",
            name,
            flags=re.IGNORECASE,
        )
        is not None
    )


def _rpm_versions_for_names(
    getter: Callable[[str], Any],
    hosts: list[str],
    names: list[str],
    tools: list[str],
) -> dict[str, list[str]]:
    """Sample SRPM upstream versions for RPM soft-label keepers."""
    if not names or not hosts:
        return {}
    tools.append("bomq_builds")
    versions: dict[str, list[str]] = {}
    for name in names:
        key = name.casefold()
        found = list(versions.get(key, []))
        for host in hosts:
            for version in _build_versions(getter, host, name):
                if version not in found:
                    found.append(version)
            if len(found) >= 8:
                break
        versions[key] = found[:8]
    return versions


def _ecosystem_versions_for_hits(
    getter: Callable[[str], Any],
    hosts: list[str],
    hits: list[CandidateHit],
    tools: list[str],
) -> dict[str, list[str]]:
    """Sample nested component versions for ecosystem soft-label keepers."""
    if not hits or not hosts:
        return {}
    tools.append("bomq_component_versions")
    versions: dict[str, list[str]] = {}
    for hit in hits:
        key = hit.name.casefold()
        found = list(versions.get(key, []))
        for host in hosts:
            for version in _component_versions(getter, host, hit.name, hit.type):
                if version not in found:
                    found.append(version)
                if len(found) >= 8:
                    break
            if len(found) >= 8:
                break
        versions[key] = found[:8]
    return versions


def _build_versions(getter: Callable[[str], Any], host: str, name: str) -> list[str]:
    """Fetch and normalize upstream versions from bomq build search."""
    query = urllib.parse.urlencode({"name": name, "strict": "true", "limit": "20"})
    payload = getter(f"{host}/api/v0/search/builds?{query}")
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return []
    versions: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        raw = item.get("build_version") or item.get("version")
        if not isinstance(raw, str) or not raw.strip():
            continue
        version = _upstream_version(raw)
        if version and version not in versions:
            versions.append(version)
        if len(versions) >= 8:
            break
    return versions


def _component_versions(
    getter: Callable[[str], Any],
    host: str,
    name: str,
    component_type: str,
) -> list[str]:
    """Upstream versions from bomq component search for one ecosystem type."""
    query = urllib.parse.urlencode(
        {
            "name": name,
            "strict": "true",
            "include_types": component_type,
            "limit": "20",
        }
    )
    payload = getter(f"{host}/api/v0/search/components?{query}")
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return []
    versions: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        for source in item.get("sources") or []:
            if not isinstance(source, dict):
                continue
            for component in source.get("components") or []:
                if not isinstance(component, dict):
                    continue
                if str(component.get("name") or "").casefold() != name.casefold():
                    continue
                if (
                    str(component.get("type") or "").casefold()
                    != component_type.casefold()
                ):
                    continue
                raw = component.get("version")
                if not isinstance(raw, str) or not raw.strip():
                    continue
                version = _upstream_version(raw)
                if version and version not in versions:
                    versions.append(version)
                if len(versions) >= 8:
                    return versions
    return versions


def _rhcos_versions_for_names(
    getter: Callable[[str], Any],
    hosts: list[str],
    names: list[str],
    tools: list[str],
) -> dict[str, list[str]]:
    """Sample RHCOS-embedded RPM versions for soft-label keepers."""
    if not names or not hosts:
        return {}
    tools.append("bomq_rhcos")
    found: dict[str, list[str]] = {}
    for name in names:
        for host in hosts:
            versions = _rhcos_component_versions(getter, host, name)
            if versions is not None:
                found[name.casefold()] = versions
                break
    return found


def _rhcos_component_versions(
    getter: Callable[[str], Any], host: str, name: str
) -> list[str] | None:
    """Upstream versions for one RPM name inside RHCOS builds, or None if absent."""
    query = urllib.parse.urlencode(
        {
            "name": name,
            "strict": "true",
            "build_name": "rhcos*",
            "include_types": "rpm",
            "limit": "20",
        }
    )
    payload = getter(f"{host}/api/v0/search/components?{query}")
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list):
        return None
    versions: list[str] = []
    hit = False
    for item in data:
        if not isinstance(item, dict):
            continue
        build_name = str(item.get("build_name") or "")
        folded = build_name.casefold()
        if folded != "rhcos" and not folded.startswith("rhcos-"):
            continue
        if "ironic" in folded:
            continue
        hit = True
        for source in item.get("sources") or []:
            if not isinstance(source, dict):
                continue
            for component in source.get("components") or []:
                if not isinstance(component, dict):
                    continue
                if str(component.get("name") or "").casefold() != name.casefold():
                    continue
                raw = component.get("version")
                if isinstance(raw, str) and raw and raw not in versions:
                    versions.append(_upstream_version(raw))
    if not hit:
        return None
    return versions


def _rows_with_affectedness(
    planned: list[dict[str, Any]],
    versions: dict[str, list[str]],
    rhcos_versions: dict[str, list[str]],
    *,
    flaw: dict[str, Any] | None = None,
    bounds: list[VersionBound] | None = None,
) -> list[DownstreamRow]:
    """Build DownstreamRow list with affectedness and RHCOS companions."""
    rows: list[DownstreamRow] = []
    bounds_cache: dict[str, list[VersionBound]] = {}
    for item in planned:
        affectedness = None
        evidence = None
        sample_affectedness = (
            item["kind"] == "build_type" and item["value"] == "rpm"
        ) or (item["kind"] == "ecosystem" and item["value"] in _LEGAL_ECOSYSTEMS)
        if sample_affectedness:
            sample = versions.get(item["name"].casefold(), [])
            if item["compat"]:
                affectedness = None
            else:
                if bounds is not None:
                    row_bounds = bounds
                elif flaw is not None:
                    cache_key = item["name"].casefold()
                    if cache_key not in bounds_cache:
                        bounds_cache[cache_key] = _ranges_from_flaw(
                            flaw, package_name=item["name"]
                        )
                    row_bounds = bounds_cache[cache_key]
                else:
                    row_bounds = []
                affectedness = _decide_affectedness(sample, row_bounds)
            evidence = _evidence(sample)
        row = DownstreamRow(
            name=item["name"],
            affectedness=affectedness,
            evidence=evidence,
        )
        if item["kind"] == "build_type":
            row.build_type = item["value"]
        else:
            row.ecosystem = item["value"]
        rows.append(row)
        if item["name"].casefold() in rhcos_versions:
            sample = rhcos_versions[item["name"].casefold()]
            if item["compat"]:
                companion_affectedness = None
            elif bounds is not None:
                companion_affectedness = _decide_affectedness(sample, bounds)
            elif flaw is not None:
                cache_key = item["name"].casefold()
                if cache_key not in bounds_cache:
                    bounds_cache[cache_key] = _ranges_from_flaw(
                        flaw, package_name=item["name"]
                    )
                companion_affectedness = _decide_affectedness(
                    sample, bounds_cache[cache_key]
                )
            else:
                companion_affectedness = _decide_affectedness(sample, [])
            rows.append(
                DownstreamRow(
                    name=item["name"],
                    rhcos="rpm",
                    affectedness=companion_affectedness,
                    evidence=_evidence(sample),
                )
            )
    return rows


def _ranges_from_flaw(
    flaw: dict[str, Any],
    *,
    package_name: str | None = None,
) -> list[VersionBound]:
    """Version bounds from OSV upstream_data, else advisory text."""
    upstream = flaw.get("upstream_data")
    if isinstance(upstream, dict):
        bounds = _osv_bounds(upstream, package_name=package_name)
        if bounds:
            return bounds
    text = _advisory_text(flaw)
    return _advisory_bounds(text)


def _osv_package_name(affected: dict[str, Any]) -> str | None:
    """Package name (or PURL path) from one OSV affected entry."""
    package = affected.get("package")
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    purl = package.get("purl")
    if isinstance(purl, str) and "/" in purl:
        # pkg:golang/github.com/foo/bar@v1 -> github.com/foo/bar
        path = purl.split("/", 1)[1]
        return path.split("@", 1)[0].strip() or None
    return None


def _osv_package_matches(entry_name: str | None, row_name: str) -> bool:
    """True when an OSV package name refers to the same project as ``row_name``."""
    if not entry_name:
        return True
    folded = entry_name.casefold()
    row = row_name.casefold().rstrip("/")
    if folded == row or folded == row.rsplit("/", 1)[-1]:
        return True
    return bool(row.endswith("/" + folded) or folded.endswith("/" + row))


def _osv_bounds(
    upstream: dict[str, Any],
    *,
    package_name: str | None = None,
) -> list[VersionBound]:
    """Collect version bounds from OSV ``affected`` entries.

    ``GIT`` ranges are skipped (commit hashes are not versions). When
    ``package_name`` is set, prefer entries whose package matches that name;
    unnamed entries stay global. If every entry names a package and none
    match, return no bounds rather than another package's interval.
    """
    affected_list = [
        affected
        for affected in (upstream.get("affected") or [])
        if isinstance(affected, dict)
    ]
    if package_name:
        named = [
            affected
            for affected in affected_list
            if _osv_package_name(affected) is not None
        ]
        matched = [
            affected
            for affected in affected_list
            if _osv_package_matches(_osv_package_name(affected), package_name)
        ]
        # All entries name a package and none match this row: do not fall
        # back to another package's interval.
        if named and len(named) == len(affected_list) and not matched:
            return []
        if matched:
            affected_list = matched

    bounds: list[VersionBound] = []
    for affected in affected_list:
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue
            range_type = str(version_range.get("type") or "").upper()
            if range_type == "GIT":
                continue
            introduced: str | None = None
            for event in version_range.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if "introduced" in event and isinstance(event["introduced"], str):
                    introduced = event["introduced"]
                if "fixed" in event and isinstance(event["fixed"], str):
                    bounds.append(VersionBound(introduced, event["fixed"], None))
                    introduced = None
                if "last_affected" in event and isinstance(event["last_affected"], str):
                    bounds.append(
                        VersionBound(introduced, None, event["last_affected"])
                    )
                    introduced = None
            if introduced is not None:
                bounds.append(VersionBound(introduced, None, None))
        for version in affected.get("versions") or []:
            if isinstance(version, str) and version:
                bounds.append(VersionBound(version, None, version))
    return bounds


def _clause_around(text: str, start: int, end: int) -> str:
    """Sentence / clause containing ``text[start:end]`` for negation checks."""
    left = max(
        text.rfind(".", 0, start), text.rfind(";", 0, start), text.rfind("\n", 0, start)
    )
    right_candidates = [
        pos
        for pos in (text.find(".", end), text.find(";", end), text.find("\n", end))
        if pos != -1
    ]
    right = min(right_candidates) if right_candidates else len(text)
    return text[left + 1 : right]


def _advisory_bounds(text: str) -> list[VersionBound]:
    """Parse introduced/fixed/last_affected bounds from advisory prose."""
    bounds: list[VersionBound] = []
    paired_spans: list[tuple[int, int]] = []
    for match in _THROUGH_RE.finditer(text):
        clause = _clause_around(text, match.start(), match.end())
        if re.search(r"\bnot\s+affected\b", clause, flags=re.IGNORECASE):
            continue
        bounds.append(VersionBound(match.group(1), None, match.group(2)))
        paired_spans.append(match.span())
    for match in _BARE_THROUGH_RE.finditer(text):
        if any(start <= match.start() < end for start, end in paired_spans):
            continue
        clause = _clause_around(text, match.start(), match.end())
        if re.search(r"\bnot\s+affected\b", clause, flags=re.IGNORECASE):
            continue
        bounds.append(VersionBound(None, None, match.group(1)))
    for match in _GTE_RE.finditer(text):
        bounds.append(VersionBound(match.group(1), None, None))
    for match in _LT_RE.finditer(text):
        bounds.append(VersionBound(None, match.group(1), None))
    return bounds


def _decide_affectedness(versions: list[str], bounds: list[VersionBound]) -> str | None:
    """SUSE-style: any overlapping sample is AFFECTED; none overlapping is NOTAFFECTED."""
    if not versions or not bounds:
        return "UNKNOWN"
    if any(
        any(_version_in_bound(version, bound) for bound in bounds)
        for version in versions
    ):
        return "AFFECTED"
    return "NOTAFFECTED"


def _version_in_bound(version: str, bound: VersionBound) -> bool:
    """True when ``version`` falls inside one VersionBound interval."""
    key = _version_key(version)
    below_introduced = (
        bool(bound.introduced)
        and bound.introduced != "0"
        and _version_compare(key, _version_key(bound.introduced)) < 0
    )
    at_or_after_fixed = (
        bool(bound.fixed) and _version_compare(key, _version_key(bound.fixed)) >= 0
    )
    after_last_affected = (
        bool(bound.last_affected)
        and _version_compare(key, _version_key(bound.last_affected)) > 0
    )
    return not (below_introduced or at_or_after_fixed or after_last_affected)


def _strip_leading_v(version: str) -> str:
    """Drop a leading ``v``/``V`` before a digit in a version string."""
    text = version.strip()
    if len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        return text[1:]
    return text


# Kind 0 = numeric token, kind 1 = alphabetic (prerelease) token.
_VersionPart = tuple[int, int] | tuple[int, str]


def _version_key(version: str) -> tuple[_VersionPart, ...]:
    """Tokenize a version into comparable numeric and alphabetic parts."""
    parts: list[_VersionPart] = []
    for match in _VERSION_PART_RE.finditer(_strip_leading_v(version)):
        token = match.group()
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token.casefold()))
    return tuple(parts)


def _version_part_compare(left: _VersionPart, right: _VersionPart) -> int:
    """Compare one version token pair; numeric sorts before alphabetic."""
    left_kind, left_value = left
    right_kind, right_value = right
    if left_kind != right_kind:
        return -1 if left_kind < right_kind else 1
    if isinstance(left_value, int) and isinstance(right_value, int):
        if left_value < right_value:
            return -1
        if left_value > right_value:
            return 1
        return 0
    left_text = str(left_value)
    right_text = str(right_value)
    if left_text < right_text:
        return -1
    if left_text > right_text:
        return 1
    return 0


def _version_compare(
    left: tuple[_VersionPart, ...],
    right: tuple[_VersionPart, ...],
) -> int:
    """Order versions so prerelease suffixes sort before the final release.

    Shared numeric/alpha prefixes compare normally. A leftover alphabetic
    suffix (``1.2.0rc1`` vs ``1.2.0``) is older; a leftover numeric suffix
    (``1.2.0.1`` vs ``1.2.0``) is newer.
    """
    n = min(len(left), len(right))
    for index in range(n):
        ordered = _version_part_compare(left[index], right[index])
        if ordered:
            return ordered
    if len(left) == len(right):
        return 0
    longer = left if len(left) > len(right) else right
    sign = 1 if len(left) > len(right) else -1
    # First leftover token: alphabetic => prerelease (older); numeric => newer.
    kind, _value = longer[n]
    if kind == 1:
        return -sign
    return sign


def _upstream_version(build_version: str) -> str:
    """Strip epoch, leading v, and RPM release from a build version."""
    text = build_version.strip()
    if ":" in text:
        epoch, rest = text.split(":", 1)
        if epoch.isdigit():
            text = rest
    if len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        text = text[1:]
    if "-" in text:
        head, tail = text.split("-", 1)
        if tail[:1].isdigit():
            return head
    return text


def _evidence(versions: list[str]) -> str | None:
    """Short slash-joined version sample for affectedness evidence, or None."""
    if not versions:
        return None
    return " / ".join(versions[:4])


def _empty_explanation() -> str:
    return (
        "The flaw has no component names to map, so no downstream catalog "
        "search was run and no downstream names are suggested."
    )


def _kernel_explanation() -> str:
    return (
        "This flaw names a kernel component. Downstream rebuild rules do not "
        "apply to product kernels, so no downstream names are suggested and "
        "no catalog search is recorded for them."
    )


def _catalog_unavailable_explanation(seeds: list[str]) -> str:
    seed_text = ", ".join(seeds)
    return (
        f"Product and community catalog lookups failed for {seed_text}, so "
        "downstream names could not be confirmed. Existing mappings should be "
        "left unchanged until the catalogs respond again."
    )


def _candidate_explanation(
    seeds: list[str], candidates: list[CandidateHit], promiscuous: list[str]
) -> str:
    """Human-readable summary of soft-label keepers after catalog prefetch."""
    seed_text = ", ".join(seeds)
    keepers = [hit.name for hit in candidates if hit.soft_label in _KEEP_LABELS]
    note = ""
    if promiscuous:
        note = (
            " Wide catalog results were narrowed with *{seed}, {seed}*, and "
            "compat-{seed}* because a host exceeded the promiscuous threshold."
        )
    if not keepers:
        return (
            f"No same-project downstream name was confirmed in the product or "
            f"community catalogs for {seed_text}.{note}"
        )
    return (
        f"Catalog candidates for {seed_text} include soft-label keepers "
        f"{', '.join(keepers[:12])}.{note}"
    )


def _explanation(seeds: list[str], rows: list[DownstreamRow]) -> str:
    """Human-readable summary of final downstream rows for one flaw."""
    seed_text = ", ".join(seeds)
    names = ", ".join(row.name for row in rows if row.rhcos is None)
    if not names:
        return (
            f"No same-project downstream name was confirmed in the product or "
            f"community catalogs for {seed_text}. Names that failed the rebuild, "
            "subpackage, or catalog checks were left out."
        )
    return (
        f"Downstream names for {seed_text} were taken from catalog rows and "
        f"Fedora packages on the same upstream project: {names}. Subpackages, "
        "unrelated rebuilds, and unconfirmed names were left out."
    )


# Public helpers used by the agent toolset.
def query_bomq_components(
    name: str,
    *,
    glob: bool = False,
    community: bool = False,
    get_json: Callable[[str], Any] | None = None,
) -> list[dict[str, Any]]:
    """Query one bomq host for component catalog rows."""
    settings = get_settings()
    host = (settings.bomq_community_url if community else settings.bomq_url).rstrip("/")
    if not host:
        return []
    getter = get_json or http_get_json
    hits = _component_rows(getter, host, name, glob=glob or ("*" in name))
    return [
        {
            "name": hit.name,
            "type": hit.type,
            "build_count": hit.build_count,
        }
        for hit in hits
    ]


def _is_rhcos_only(entry: Any) -> bool:
    """True when an entry is an RHCOS companion with no build_type/ecosystem."""
    return (
        getattr(entry, "rhcos", None) is not None
        and not getattr(entry, "build_type", None)
        and not getattr(entry, "ecosystem", None)
    )


def apply_usage_policy(
    entries: list[Any],
    *,
    vulnerable_unit: str,
    caller_role: str,
    runs_vulnerable_code: list[str],
    importer_only: list[str],
    candidates: list[CandidateHit],
    explanation: str,
    confirm_name: Callable[[str], list[CatalogHit]] | None = None,
    entry_factory: Callable[..., Any] | None = None,
) -> tuple[list[Any], str]:
    """Keep names that run the buggy code; gate importer-only by build count.

    Tool-confirmed ``runs_vulnerable_code`` names are restored for every
    caller role. Importer build-count drops apply only when ``caller_role``
    is ``product_feature``. RHCOS companions are kept alongside surviving
    RPM rows and never overwrite them in the name map.
    """
    counts = _build_counts_from_candidates(candidates)
    catalog_by_name: dict[str, list[CatalogHit]] = {}
    display_names: dict[str, str] = {}
    for hit in candidates:
        folded = hit.name.casefold()
        display_names.setdefault(folded, hit.name)
        catalog_by_name.setdefault(folded, []).append(
            CatalogHit(hit.name, hit.type, hit.build_count)
        )

    runs = {name.casefold() for name in runs_vulnerable_code if name.strip()}
    importers = {name.casefold() for name in importer_only if name.strip()}
    factory = entry_factory or _default_manifest_entry
    gate_importers = caller_role == "product_feature"

    # Separate RHCOS companions so they cannot overwrite RPM rows by name.
    by_name: dict[str, Any] = {}
    rhcos_by_name: dict[str, Any] = {}
    for entry in entries:
        name = getattr(entry, "name", None)
        if not isinstance(name, str) or not name.strip():
            continue
        folded = name.casefold()
        if _is_rhcos_only(entry):
            rhcos_by_name.setdefault(folded, entry)
            continue
        by_name.setdefault(folded, entry)

    omitted: list[str] = []
    kept_na: list[str] = []

    if gate_importers:
        for folded in list(by_name):
            count = counts.get(folded)
            if folded in importers:
                if count is not None and count >= IMPORTER_AFFECT_LIMIT:
                    omitted.append(
                        f"{display_names.get(folded, folded)} ({count} builds)"
                    )
                    by_name.pop(folded, None)
                    continue
                entry = by_name[folded]
                entry.affectedness = "NOTAFFECTED"
                kept_na.append(
                    f"{getattr(entry, 'name', folded)}"
                    f" ({count if count is not None else 'unknown'} builds)"
                )
                continue
            if folded in runs:
                continue
            # High-count name not classified as running the vulnerable code.
            if count is not None and count >= IMPORTER_AFFECT_LIMIT:
                omitted.append(f"{display_names.get(folded, folded)} ({count} builds)")
                by_name.pop(folded, None)

    for name in runs_vulnerable_code:
        folded = name.casefold()
        if folded in by_name:
            continue
        hits = catalog_by_name.get(folded) or []
        if not hits and confirm_name is not None:
            hits = confirm_name(name)
            for hit in hits:
                catalog_by_name.setdefault(hit.name.casefold(), []).append(hit)
                if hit.build_count is not None:
                    current = counts.get(hit.name.casefold())
                    if current is None or hit.build_count > current:
                        counts[hit.name.casefold()] = hit.build_count
                display_names.setdefault(hit.name.casefold(), hit.name)
        if not hits:
            continue
        entry = _manifest_entry_from_hits(name, hits, factory)
        if entry is not None:
            by_name[folded] = entry

    if gate_importers:
        for name in importer_only:
            folded = name.casefold()
            if folded in by_name or folded in runs:
                continue
            count = counts.get(folded)
            if count is not None and count >= IMPORTER_AFFECT_LIMIT:
                omitted.append(f"{display_names.get(folded, name)} ({count} builds)")
                continue
            hits = catalog_by_name.get(folded) or []
            if not hits:
                continue
            entry = _manifest_entry_from_hits(name, hits, factory)
            if entry is None:
                continue
            entry.affectedness = "NOTAFFECTED"
            by_name[folded] = entry
            kept_na.append(
                f"{getattr(entry, 'name', name)}"
                f" ({count if count is not None else 'unknown'} builds)"
            )

    note_parts: list[str] = []
    if omitted:
        note_parts.append(
            "Omitted importer-only catalog names with "
            f"{IMPORTER_AFFECT_LIMIT}+ builds that do not run "
            f"{vulnerable_unit or 'the vulnerable unit'}: {', '.join(omitted)}."
        )
    if kept_na:
        note_parts.append(
            "Kept importer-only names below the affect limit as NOTAFFECTED "
            f"because they only link a shared module: {', '.join(kept_na)}."
        )
    note = " ".join(note_parts)
    if note and note not in explanation:
        explanation = f"{explanation.rstrip()} {note}".strip() if explanation else note

    # Preserve relative order of surviving original entries, then additions.
    # Re-attach RHCOS companions only when the RPM row for that name survived.
    ordered: list[Any] = []
    seen: set[str] = set()
    for entry in entries:
        name = getattr(entry, "name", None)
        if not isinstance(name, str):
            continue
        folded = name.casefold()
        if _is_rhcos_only(entry):
            continue
        if folded in by_name and folded not in seen:
            ordered.append(by_name[folded])
            seen.add(folded)
            companion = rhcos_by_name.get(folded)
            if companion is not None:
                ordered.append(companion)
    for folded, entry in by_name.items():
        if folded not in seen:
            ordered.append(entry)
            seen.add(folded)
            companion = rhcos_by_name.get(folded)
            if companion is not None:
                ordered.append(companion)
    return ordered, explanation


def _build_counts_from_candidates(candidates: list[CandidateHit]) -> dict[str, int]:
    """Max bomq build_count per candidate name (casefolded)."""
    counts: dict[str, int] = {}
    for hit in candidates:
        if hit.build_count is None:
            continue
        folded = hit.name.casefold()
        current = counts.get(folded)
        if current is None or hit.build_count > current:
            counts[folded] = hit.build_count
    return counts


def _default_manifest_entry(**kwargs: Any) -> Any:
    from aegis_ai.features.cve.data_models import ManifestComponentEntry

    return ManifestComponentEntry(**kwargs)


def _manifest_entry_from_hits(
    name: str,
    hits: list[CatalogHit],
    factory: Callable[..., Any],
) -> Any | None:
    """Build a ManifestComponentEntry from catalog hits, or None if unclassifiable."""
    classified = _classify(hits, _is_module_path(name))
    if classified is None:
        return None
    kind, value = classified
    kwargs: dict[str, Any] = {
        "name": name,
        "affectedness": "UNKNOWN",
        "evidence": None,
    }
    if kind == "build_type":
        kwargs["build_type"] = value
    else:
        kwargs["ecosystem"] = value
    return factory(**kwargs)


def query_bomq_build_versions(
    name: str,
    *,
    community: bool = False,
    get_json: Callable[[str], Any] | None = None,
) -> list[str]:
    """Sample upstream versions from bomq build search."""
    settings = get_settings()
    host = (settings.bomq_community_url if community else settings.bomq_url).rstrip("/")
    if not host:
        return []
    getter = get_json or http_get_json
    return _build_versions(getter, host, name)


def query_anitya_projects(
    name: str,
    *,
    get_json: Callable[[str], Any] | None = None,
) -> list[dict[str, Any]]:
    """Return same-name Anitya projects with Fedora package names."""
    settings = get_settings()
    base = (settings.anitya_url or "").rstrip("/")
    if not base:
        return []
    getter = get_json or http_get_json
    projects = _anitya_projects(getter, base, name)
    result: list[dict[str, Any]] = []
    for project in projects:
        packages = _fedora_packages(getter, base, project.get("id"))
        result.append(
            {
                "id": project.get("id"),
                "name": project.get("name"),
                "backend": project.get("backend"),
                "homepage": project.get("homepage"),
                "fedora_packages": packages,
            }
        )
    return result
