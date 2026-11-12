"""
Suggest manifest component and state evaluation suite.

Goldens are static: one-time bomq catalog plus ``bomq search -k build``
keep/drop results in ``manifest_component_goldens.json``. The scorer does
not call bomq. Each required row carries ``source_component`` (flaw seed);
top-level ``ranges`` soft-scores advisory bound tokens (or ``[]`` when the
text states none).

The feature task reads bomq/Anitya responses from the checked-in
``evals/catalog_cache/`` (see ``evals/utils/catalog_cache.py``). Populate
bomq with ``make populate-catalog-cache`` (real ``AEGIS_BOMQ_*`` hosts).
CI fetches public Anitya misses and dumps them for import; uncached bomq
tool URLs are blocked instead of failing the case.

Input is a CVE id. The task passes the cached flaw JSON (components and
aegis_meta) as static context, the same seed the bot has after
suggest_components.

Runnable: pytest evals/features/cve/test_suggest_manifest_component_and_state.py
Optional: --sample N, AEGIS_EVALS_SUGGEST_MANIFEST_COMPONENT_SAMPLE,
or AEGIS_EVALS_SUGGEST_MANIFEST_COMPONENT_CVE_IDS.

Schema tests, the scorer, and the feature eval all execute.
"""

import json
import os
import random
from pathlib import Path
from typing import Any

import pytest
from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis_ai.features.cve.downstream import (
    _is_clear_rebuild,
    _is_compat,
    _is_openshift_fork_rebuild,
    _is_subpackage,
    _is_version_package,
    _related_to_seed,
)
from evals.features.common import (
    FeatureMetricsEvaluator,
    ToolsUsedEvaluator,
    reflect_confidence,
    run_evaluation,
)
from evals.utils.osidb_cache import OSIDB_CACHE_DIR, read_cache_json

SAMPLE_SEED = int(os.getenv("AEGIS_EVALS_SAMPLE_SEED", "42"))
_EVAL_DIR = Path(__file__).resolve().parent
GOLDENS_PATH = _EVAL_DIR / "manifest_component_goldens.json"

# Locked sample. Order matches the eval plan table.
DEFAULT_CVE_IDS = [
    "CVE-2026-96275",
    "CVE-2026-14668",
    "CVE-2026-65183",
    "CVE-2026-18090",
    "CVE-2026-90439",
    "CVE-2026-76014",
    "CVE-2026-90801",
    "CVE-2026-63266",
    "CVE-2026-55193",
    "CVE-2026-57224",
    "CVE-2026-68515",
    "CVE-2026-73073",
    "CVE-2026-19024",
    "CVE-2026-61723",
    "CVE-2026-84975",
    "CVE-2026-50149",
    "CVE-2026-79776",
    "CVE-2026-71556",
    "CVE-2025-71405",
    "CVE-2026-96404",
    "CVE-2026-76802",
    "CVE-2026-100658",
    "CVE-2026-12816",
    "CVE-2026-61373",
    "CVE-2026-83606",
    "CVE-2026-85124",
    "CVE-2026-66069",
    "CVE-2026-47683",
    "CVE-2026-72887",
    "CVE-2026-47489",
    "CVE-2026-102577",
    "CVE-2026-1199",
    "CVE-2026-50291",
    "CVE-2026-119566",
]

BUILD_TYPES = {"rpm", "container", "maven", "generic"}
ECOSYSTEMS = {"cargo", "gem", "golang", "maven", "npm", "pypi", "generic"}


def load_goldens() -> dict[str, dict[str, Any]]:
    """Load the static golden file."""
    with GOLDENS_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise TypeError(f"{GOLDENS_PATH.name} must be a JSON object")
    return data


def _norm(value: Any) -> str:
    """Casefold and strip a value for golden-row comparisons."""
    return str(value or "").strip().casefold()


def _primary_key(row: dict[str, Any]) -> tuple[str, str] | None:
    """Return the single legal search key, or None.

    ``ecosystem: rpm`` is never legal. A row with both keys set is not legal.
    """
    build_type = _norm(row.get("build_type"))
    ecosystem = _norm(row.get("ecosystem"))
    if ecosystem == "rpm" or (build_type and ecosystem):
        return None
    if build_type:
        if build_type not in BUILD_TYPES:
            return None
        return ("build_type", build_type)
    if ecosystem:
        if ecosystem not in ECOSYSTEMS:
            return None
        return ("ecosystem", ecosystem)
    return None


def _rows_from_output(output: Any) -> list[dict[str, Any]]:
    """Read suggestion rows without requiring the feature model."""
    raw = output
    if not isinstance(output, (list, dict)):
        for attr in ("components", "manifest_components", "rows"):
            candidate = getattr(output, attr, None)
            if candidate is not None:
                raw = candidate
                break
    if isinstance(raw, dict):
        for key in ("components", "manifest_components", "rows"):
            if key in raw:
                raw = raw[key]
                break
        else:
            raw = []
    rows: list[dict[str, Any]] = []
    for item in raw or []:
        if isinstance(item, str):
            rows.append({"name": item})
        elif isinstance(item, dict):
            rows.append(item)
        else:
            rows.append(
                {
                    "name": getattr(item, "name", ""),
                    "build_type": getattr(item, "build_type", None),
                    "ecosystem": getattr(item, "ecosystem", None),
                    "rhcos": getattr(item, "rhcos", None),
                    "source_component": getattr(item, "source_component", None),
                }
            )
    return rows


def _same_project(extra: str, anchors: list[str]) -> bool:
    """True when ``extra`` is same-project packaging of an anchor.

    Uses the feature keep-identity rules (version packages, clear rebuilds,
    compat, openshift forks, module parent/child). Substring overlap alone is
    not enough: subpackages (``nginx-devel``) and lookalikes (``python-nginx``)
    are rejected.
    """
    folded = _norm(extra)
    if not folded or _is_subpackage(folded):
        return False
    for anchor in anchors:
        if not anchor:
            continue
        if folded == anchor:
            return True
        if "/" in folded or "/" in anchor:
            if _related_to_seed(folded, [anchor]) or _is_openshift_fork_rebuild(
                extra, anchor
            ):
                return True
            continue
        if (
            _is_compat(extra, anchor)
            or _is_version_package(extra, anchor)
            or _is_clear_rebuild(extra, anchor)
        ):
            return True
    return False


def _rows_for_names(
    produced: list[tuple[str, dict[str, Any]]], names: list[str] | set[str]
) -> list[dict[str, Any]]:
    """Produced row dicts whose casefolded name is in ``names``."""
    wanted = {_norm(name) for name in names}
    return [row for name, row in produced if name in wanted]


def _missing_detail(
    req: dict[str, Any], produced: list[tuple[str, dict[str, Any]]]
) -> str:
    """Expected golden row plus same-name produced rows (or none)."""
    req_name = _norm(req.get("name"))
    same = [row for name, row in produced if name == req_name]
    got = same if same else "none"
    return f"expected {req!r}, got {got!r}"


def _row_matches_required(
    row: dict[str, Any],
    expected_key: tuple[str, str] | None,
    expected_rhcos: str,
    expected_source: str | None = None,
) -> bool:
    """True when produced row matches the required search key and checked fields."""
    if expected_key is None or _primary_key(row) != expected_key:
        return False
    if expected_rhcos and _norm(row.get("rhcos")) != expected_rhcos:
        return False
    return expected_source is None or row.get("source_component") == expected_source


def _strip_v(version: Any) -> str:
    """Strip a leading ``v`` from a version token."""
    text = str(version or "").strip()
    if len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        return text[1:]
    return text


def _ranges_from_output(output: Any) -> list[dict[str, Any]]:
    """Read the sibling ``ranges`` list from a feature output."""
    raw = getattr(output, "ranges", None)
    if raw is None and isinstance(output, dict):
        raw = output.get("ranges")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _event_field_tokens(entry: dict[str, Any], field: str) -> set[str]:
    """Version tokens for one event field from a produced ranges entry."""
    tokens: set[str] = set()
    for block in entry.get("ranges") or []:
        if not isinstance(block, dict):
            continue
        for event in block.get("events") or []:
            if not isinstance(event, dict):
                continue
            value = event.get(field)
            if value is not None and str(value).strip():
                tokens.add(_strip_v(value))
    return tokens


def _versions_tokens(entry: dict[str, Any]) -> set[str]:
    """Top-level ``versions`` tokens from a produced ranges entry."""
    tokens: set[str] = set()
    for value in entry.get("versions") or []:
        if value is not None and str(value).strip():
            tokens.add(_strip_v(value))
    return tokens


def score_ranges(
    golden: dict[str, Any], produced_ranges: list[dict[str, Any]]
) -> tuple[float, str | None]:
    """Soft-score sibling ranges when the golden sets a ``ranges`` list.

    Empty golden ``ranges`` requires no produced entries. Otherwise each
    expected seed must appear, and every listed ``fixed`` / ``last_affected`` /
    ``introduced`` token must show up on that field in some event. Listed
    ``versions`` tokens must appear on the produced entry's top-level
    ``versions`` list. Extra events, versions, or seeds are ignored. Missing
    ``ranges`` on the golden skips this check entirely.
    """
    if "ranges" not in golden:
        return 1.0, None
    expected = golden.get("ranges")
    if not isinstance(expected, list):
        return 0.0, "golden ranges is not a list"
    if not expected:
        if produced_ranges:
            return (
                0.0,
                f"expected no ranges, got {produced_ranges!r}",
            )
        return 1.0, None

    by_seed: dict[str, dict[str, Any]] = {}
    for entry in produced_ranges:
        seed = entry.get("source_component")
        if isinstance(seed, str) and seed.strip() and seed not in by_seed:
            by_seed[seed] = entry

    for req in expected:
        if not isinstance(req, dict):
            return 0.0, f"golden ranges entry is not an object: {req!r}"
        seed = req.get("source_component")
        if not isinstance(seed, str) or not seed.strip():
            return 0.0, f"golden ranges entry missing source_component: {req!r}"
        produced = by_seed.get(seed)
        if produced is None:
            return (
                0.0,
                f"missing ranges for source_component {seed!r}, got {produced_ranges!r}",
            )
        for field in ("fixed", "last_affected", "introduced"):
            wanted = [
                _strip_v(token) for token in req.get(field) or [] if str(token).strip()
            ]
            if not wanted:
                continue
            have = _event_field_tokens(produced, field)
            missing = [token for token in wanted if token not in have]
            if missing:
                return (
                    0.0,
                    (
                        f"source_component {seed!r} missing {field} {missing}, "
                        f"got {produced!r}"
                    ),
                )
        wanted_versions = [
            _strip_v(token) for token in req.get("versions") or [] if str(token).strip()
        ]
        if wanted_versions:
            have_versions = _versions_tokens(produced)
            missing_versions = [
                token for token in wanted_versions if token not in have_versions
            ]
            if missing_versions:
                return (
                    0.0,
                    (
                        f"source_component {seed!r} missing versions "
                        f"{missing_versions}, got {produced!r}"
                    ),
                )
    return 1.0, None


def score_manifest(
    golden: dict[str, Any],
    rows: list[dict[str, Any]],
    ranges: list[dict[str, Any]] | None = None,
) -> tuple[float, str | None]:
    """Score produced rows against one golden.

    Name overlap is Jaccard of required names against key-matched produced
    names, plus a 0.5 primary-name bonus (same shape as
    ComponentsOverlapEvaluator). When ``allow_extra_same_project`` is set,
    extras that match feature keep-identity rules against a required or seed
    name are ignored. Names listed in ``allow_extra_names`` are also ignored
    (Anitya same-upstream packages that are not clear rebuilds). Subpackages
    and lookalike substring hits score 0. Other extras score 0. A required
    row counts only when its build_type or ecosystem matches exactly, and
    when ``source_component`` is set on the golden row it must match exactly.
    Sibling ``ranges`` are soft-scored when the golden sets a ``ranges`` list.
    ``require_full_path`` rejects a produced name that is only the final path
    segment of a required Go, Maven, or scoped-npm name. Agreeing same-name
    duplicates still match; a correct row plus a conflicting same-name
    duplicate scores 0.
    """
    range_score, range_reason = score_ranges(golden, ranges or [])
    if range_score < 1.0:
        return 0.0, range_reason

    required = list(golden.get("required") or [])
    allow_extra = bool(golden.get("allow_extra_same_project"))
    require_full = bool(
        golden.get("require_full_path") or golden.get("forbid_short_go")
    )
    forbid = {_norm(name) for name in golden.get("forbid") or []}
    allow_names = {_norm(name) for name in golden.get("allow_extra_names") or []}

    produced: list[tuple[str, dict[str, Any]]] = []
    for row in rows:
        name = _norm(row.get("name"))
        if name:
            produced.append((name, row))
    got_names = [name for name, _row in produced]
    got_set = set(got_names)

    forbidden_hits = sorted(forbid & got_set)
    if forbidden_hits:
        return (
            0.0,
            (
                f"got {got_names}, forbidden {forbidden_hits}, "
                f"rows {_rows_for_names(produced, forbidden_hits)!r}"
            ),
        )

    req_names = [_norm(row["name"]) for row in required]
    req_set = set(req_names)
    if require_full:
        shorts = {
            name.rsplit("/", 1)[-1]
            for name in req_names
            if "/" in name and name.rsplit("/", 1)[-1] not in req_set
        }
        short_hits = [name for name in got_names if name in shorts]
        if short_hits:
            return (
                0.0,
                (
                    f"got {got_names}, shortened path {short_hits}, "
                    f"rows {_rows_for_names(produced, short_hits)!r}"
                ),
            )

    matched: set[str] = set()
    missing: list[dict[str, Any]] = []
    for req in required:
        req_name = _norm(req["name"])
        expected_key = _primary_key(req)
        expected_rhcos = _norm(req.get("rhcos"))
        expected_source = req.get("source_component")
        if not isinstance(expected_source, str) or not expected_source.strip():
            expected_source = None
        same_name = [row for name, row in produced if name == req_name]
        hits = [
            row
            for row in same_name
            if _row_matches_required(row, expected_key, expected_rhcos, expected_source)
        ]
        conflicts = [
            row
            for row in same_name
            if row not in hits
            # RHCOS companions share the name but are not conflicting duplicates.
            and not (
                _norm(row.get("rhcos"))
                and not _norm(row.get("build_type"))
                and not _norm(row.get("ecosystem"))
            )
        ]
        if hits and conflicts:
            return (
                0.0,
                (
                    f"got {got_names}, conflicting duplicate for {req_name}, "
                    f"expected {req!r}, rows {same_name!r}"
                ),
            )
        if hits:
            matched.add(req_name)
        else:
            missing.append(req)

    extra_names = [name for name in got_names if name not in req_set]
    if extra_names and not allow_extra:
        return (
            0.0,
            (
                f"got {got_names}, expected {req_names}, unexpected {extra_names}, "
                f"rows {_rows_for_names(produced, extra_names)!r}"
            ),
        )
    if extra_names:
        anchors = list(req_set)
        seed = _norm(golden.get("seed"))
        if seed:
            anchors.append(seed)
        wrong = [
            name
            for name in extra_names
            if name not in allow_names and not _same_project(name, anchors)
        ]
        if wrong:
            return (
                0.0,
                (
                    f"got {got_names}, expected {req_names}, wrong-project {wrong}, "
                    f"rows {_rows_for_names(produced, wrong)!r}"
                ),
            )

    if not req_set:
        return 1.0, None

    if allow_extra:
        union = len(req_set)
    else:
        union = len(req_set | got_set)
    jaccard = len(matched) / union if union else 0.0
    primary_bonus = 0.5 if req_names[0] in matched else 0.0
    score = (jaccard * 0.5) + primary_bonus
    if score >= 1.0:
        return 1.0, None
    details = [_missing_detail(req, produced) for req in missing]
    return (
        score,
        f"got {got_names}, expected {req_names}, missing {details}",
    )


class ManifestComponentEvaluator(Evaluator[str, Any]):
    """Required-name overlap, primary search key, source_component, and soft ranges."""

    def evaluate(self, ctx: EvaluatorContext[str, Any]) -> EvaluationReason:
        """Score predicted manifest rows against the CVE golden."""
        golden = ctx.expected_output
        if not isinstance(golden, dict):
            return EvaluationReason(value=0.0, reason="golden is not an object")
        score, reason = score_manifest(
            golden,
            _rows_from_output(ctx.output),
            ranges=_ranges_from_output(ctx.output),
        )
        confidence = getattr(ctx.output, "confidence", None)
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            score = reflect_confidence(ctx, score)
        return EvaluationReason(value=score, reason=reason)


def _static_context(cve_id: str) -> dict[str, Any]:
    """Cached flaw JSON, including components and aegis_meta when present."""
    cached = read_cache_json(cve_id)
    if not cached:
        raise FileNotFoundError(
            f"No OSIDB cache entry for {cve_id} under {OSIDB_CACHE_DIR}"
        )
    return cached


async def suggest_manifest_component_and_state(cve_id: str) -> Any:
    """Run SuggestManifestComponentAndState on the cached flaw."""
    from aegis_ai.agents import rh_feature_agent
    from aegis_ai.features.cve import SuggestManifestComponentAndState

    feature = SuggestManifestComponentAndState(rh_feature_agent)
    result = await feature.exec(cve_id, static_context=_static_context(cve_id))
    return result.output


def _build_cases(
    goldens: dict[str, dict[str, Any]],
    *,
    sample_size: int | None,
    seed: int,
    cve_id_filter: set[str] | None,
) -> list[Case]:
    """Build pydantic-evals Case objects for the configured CVE sample."""
    cve_ids = list(DEFAULT_CVE_IDS)
    if cve_id_filter is not None:
        cve_ids = [cve_id for cve_id in cve_ids if cve_id in cve_id_filter]
    if sample_size is not None and sample_size < len(cve_ids):
        rng = random.Random(seed)
        cve_ids = rng.sample(cve_ids, sample_size)
    cases: list[Case] = []
    for cve_id in cve_ids:
        golden = goldens[cve_id]
        cases.append(
            Case(
                name=cve_id,
                inputs=cve_id,
                expected_output=golden,
                metadata={"seed": golden.get("seed"), "cve_id": cve_id},
            )
        )
    return cases


@pytest.fixture(scope="session")
def manifest_component_cases(request):
    """Build cases from the static golden file."""
    sample_size = request.config.getoption("sample", default=None)
    if sample_size is None:
        env_val = os.getenv("AEGIS_EVALS_SUGGEST_MANIFEST_COMPONENT_SAMPLE")
        if env_val:
            try:
                sample_size = int(env_val)
            except ValueError:
                sample_size = None
    raw = os.getenv("AEGIS_EVALS_SUGGEST_MANIFEST_COMPONENT_CVE_IDS", "").strip()
    if raw:
        cve_id_filter = {cve_id.strip() for cve_id in raw.split(",") if cve_id.strip()}
    else:
        cve_id_filter = None
    return _build_cases(
        load_goldens(),
        sample_size=sample_size,
        seed=SAMPLE_SEED,
        cve_id_filter=cve_id_filter,
    )


def _seeded_rows(
    golden: dict[str, Any], rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach the golden seed as source_component when a row omits it."""
    seed = golden.get("seed")
    out: list[dict[str, Any]] = []
    for row in rows:
        if "source_component" in row or not isinstance(seed, str):
            out.append(row)
            continue
        out.append({**row, "source_component": seed})
    return out


def _satisfying_ranges(golden: dict[str, Any]) -> list[dict[str, Any]]:
    """Minimal produced ranges that satisfy soft golden bound tokens."""
    produced: list[dict[str, Any]] = []
    for req in golden.get("ranges") or []:
        if not isinstance(req, dict):
            continue
        events: list[dict[str, str]] = []
        for field in ("introduced", "last_affected", "fixed"):
            for token in req.get(field) or []:
                text = str(token).strip()
                if text:
                    events.append({field: text})
        versions = [
            text for token in req.get("versions") or [] if (text := str(token).strip())
        ]
        entry: dict[str, Any] = {"source_component": req["source_component"]}
        if events:
            entry["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
        if versions:
            entry["versions"] = versions
        produced.append(entry)
    return produced


def _score_golden(
    golden: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[float, str | None]:
    """Score rows against a locked golden with seed and soft ranges filled."""
    return score_manifest(
        golden,
        _seeded_rows(golden, rows),
        ranges=_satisfying_ranges(golden),
    )


def test_goldens_match_locked_sample():
    """The golden file matches DEFAULT_CVE_IDS, with one legal search key each."""
    goldens = load_goldens()
    assert list(goldens) == DEFAULT_CVE_IDS
    for cve_id, golden in goldens.items():
        required = golden["required"]
        assert isinstance(required, list), cve_id
        assert isinstance(golden["allow_extra_same_project"], bool), cve_id
        assert isinstance(golden["require_full_path"], bool), cve_id
        assert isinstance(golden["ranges"], list), cve_id
        seed = golden["seed"]
        assert isinstance(seed, str) and seed.strip(), cve_id
        names = []
        for row in required:
            assert _primary_key(row) is not None, (cve_id, row)
            assert "build_type" in row or "ecosystem" in row
            assert not ("build_type" in row and "ecosystem" in row)
            assert row.get("source_component") == seed, (cve_id, row)
            names.append(_norm(row["name"]))
        assert len(names) == len(set(names)), cve_id
        if golden["require_full_path"] and required:
            assert any("/" in row["name"] for row in required), cve_id
        for name in golden.get("allow_extra_names") or []:
            assert isinstance(name, str) and name.strip(), cve_id
        for entry in golden["ranges"]:
            assert isinstance(entry, dict), cve_id
            assert (
                isinstance(entry.get("source_component"), str)
                and entry["source_component"].strip()
            ), cve_id
            assert any(
                entry.get(field)
                for field in ("fixed", "last_affected", "introduced", "versions")
            ), (cve_id, entry)


def test_score_exact_match():
    """Score exact match."""
    golden = load_goldens()["CVE-2026-65183"]
    score, reason = _score_golden(
        golden,
        [{"name": "tomcat", "build_type": "rpm"}],
    )
    assert score == 1.0
    assert reason is None


def test_score_tomcat_forbids_digit_prefixed_jws():
    """Digit-prefixed JWS tomcat rebuilds are forbidden by the golden."""
    golden = load_goldens()["CVE-2026-65183"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "tomcat", "build_type": "rpm"},
            {"name": "jws5-tomcat", "build_type": "rpm"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "jws5-tomcat" in reason


def test_score_primary_key_rejects_ecosystem_rpm():
    """Score primary key rejects ecosystem rpm."""
    golden = load_goldens()["CVE-2026-96275"]
    produced = {"name": "flatpak", "ecosystem": "rpm", "source_component": "flatpak"}
    score, reason = score_manifest(
        golden, [produced], ranges=_satisfying_ranges(golden)
    )
    assert score == 0.0
    assert reason is not None
    assert "flatpak" in reason
    assert repr(produced) in reason


def test_score_full_path_rejects_final_segment():
    """Score full path rejects final segment."""
    golden = load_goldens()["CVE-2026-79776"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "github.com/rclone/rclone", "ecosystem": "golang"},
            {"name": "rclone", "ecosystem": "golang"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "rclone" in reason


def test_score_hard_empty():
    """CVE-2026-75935 ion-java is absent from both catalogs and from Anitya."""
    golden = {
        "seed": "software.amazon.ion/ion-java",
        "required": [],
        "allow_extra_same_project": False,
        "require_full_path": True,
    }
    score, reason = score_manifest(golden, [])
    assert score == 1.0
    assert reason is None
    score, reason = score_manifest(golden, [{"name": "ion-java", "build_type": "rpm"}])
    assert score == 0.0
    assert reason is not None


def test_score_same_project_extra_is_ignored():
    """Packaging-prefix clear rebuilds beyond required names are ignored extras."""
    golden = load_goldens()["CVE-2026-90801"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "binutils", "build_type": "rpm"},
            {"name": "mingw-binutils", "build_type": "rpm"},
            {"name": "cross-binutils", "build_type": "rpm"},
        ],
    )
    assert score == 1.0
    assert reason is None


def test_score_digit_prefixed_extra_is_wrong_project():
    """Digit-prefixed product rebuilds are not same-project extras."""
    golden = load_goldens()["CVE-2026-90801"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "binutils", "build_type": "rpm"},
            {"name": "mingw-binutils", "build_type": "rpm"},
            {"name": "gcc-toolset-13-binutils", "build_type": "rpm"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "wrong-project" in reason


def test_score_anitya_allow_extra_names_are_ignored():
    """Anitya same-upstream packages that fail clear_rebuild stay allowed extras."""
    golden = load_goldens()["CVE-2026-90801"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "binutils", "build_type": "rpm"},
            {"name": "mingw-binutils", "build_type": "rpm"},
            {"name": "avr-binutils", "build_type": "rpm"},
            {"name": "arm-none-eabi-binutils-cs", "build_type": "rpm"},
        ],
    )
    assert score == 1.0
    assert reason is None


def test_score_wrong_project_extra_fails():
    """Score wrong project extra fails."""
    golden = load_goldens()["CVE-2026-90439"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "nginx", "build_type": "rpm"},
            {"name": "python-nginx", "build_type": "rpm"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "python-nginx" in reason


def test_score_subpackage_extra_is_wrong_project():
    """Subpackages must not pass as same-project extras via substring overlap."""
    golden = load_goldens()["CVE-2026-90439"]
    score, reason = _score_golden(
        golden,
        [
            {"name": "nginx", "build_type": "rpm"},
            {"name": "nginx-devel", "build_type": "rpm"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "nginx-devel" in reason
    assert "wrong-project" in reason


def test_score_ignores_affectedness_fields():
    """Scorer grades names, search keys, and source_component; affectedness is ignored."""
    golden = load_goldens()["CVE-2026-90439"]
    score, reason = _score_golden(
        golden,
        [{"name": "nginx", "build_type": "rpm", "affectedness": "NOTAFFECTED"}],
    )
    assert score == 1.0
    assert reason is None


def test_score_conflicting_duplicate_fails():
    """A matching row must not be rescued by ignoring a conflicting same-name duplicate."""
    golden = load_goldens()["CVE-2026-1199"]
    good = {"name": "zabbix", "build_type": "rpm"}
    bad = {"name": "zabbix", "ecosystem": "generic"}
    rest = [
        {"name": "zabbix6.0", "build_type": "rpm"},
        {"name": "zabbix7.0", "build_type": "rpm"},
    ]
    score, reason = _score_golden(golden, [good, bad, *rest])
    assert score == 0.0
    assert reason is not None
    assert "conflicting duplicate" in reason
    assert "zabbix" in reason
    score, reason = _score_golden(golden, [bad, good, *rest])
    assert score == 0.0
    assert reason is not None
    assert "conflicting duplicate" in reason
    score, reason = _score_golden(golden, [good, good, *rest])
    assert score == 1.0
    assert reason is None


def test_score_rhcos_companion_is_not_a_conflict():
    """An rhcos companion sharing a required name must not zero the score."""
    golden = {
        "seed": "nginx",
        "required": [{"name": "nginx", "build_type": "rpm"}],
        "allow_extra_same_project": False,
        "require_full_path": False,
    }
    score, reason = score_manifest(
        golden,
        [
            {"name": "nginx", "build_type": "rpm"},
            {"name": "nginx", "rhcos": "rpm"},
        ],
    )
    assert score == 1.0
    assert reason is None


def test_score_prometheus_usage_forbids_parent_module():
    """Score prometheus usage forbids parent module."""
    golden = load_goldens()["CVE-2026-119566"]
    score, reason = _score_golden(
        golden,
        [
            {
                "name": "github.com/openshift-priv/prometheus",
                "ecosystem": "golang",
            },
            {"name": "prometheus", "build_type": "rpm"},
            {"name": "prometheus3.13", "build_type": "rpm"},
            {"name": "prometheus3.5", "build_type": "rpm"},
            {"name": "github.com/prometheus/common", "ecosystem": "golang"},
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "github.com/prometheus/common" in reason
    score, reason = _score_golden(
        golden,
        [
            {
                "name": "github.com/openshift-priv/prometheus",
                "ecosystem": "golang",
            },
            {"name": "prometheus", "build_type": "rpm"},
            {"name": "prometheus3.13", "build_type": "rpm"},
            {"name": "prometheus3.5", "build_type": "rpm"},
        ],
    )
    assert score == 1.0
    assert reason is None


def test_score_same_project_extra_compat_is_allowed():
    """Same-project compat extras are allowed when allow_extra_same_project is set."""
    golden = {
        "seed": "openssl",
        "required": [{"name": "openssl", "build_type": "rpm"}],
        "allow_extra_same_project": True,
        "require_full_path": False,
    }
    score, reason = score_manifest(
        golden,
        [
            {"name": "openssl", "build_type": "rpm"},
            {"name": "compat-openssl11", "build_type": "rpm"},
        ],
    )
    assert score == 1.0
    assert reason is None


def test_score_source_component_mismatch_fails():
    """Required rows must carry the exact golden source_component seed."""
    golden = load_goldens()["CVE-2026-90439"]
    score, reason = score_manifest(
        golden,
        [{"name": "nginx", "build_type": "rpm", "source_component": "wrong"}],
        ranges=_satisfying_ranges(golden),
    )
    assert score < 1.0
    assert reason is not None
    assert "nginx" in reason


def test_score_soft_ranges_accepts_reordered_events():
    """Soft ranges match fixed tokens regardless of event order or range type."""
    golden = load_goldens()["CVE-2026-50291"]
    rows = _seeded_rows(
        golden,
        [
            {"name": "OpenImageIO", "build_type": "rpm"},
            {"name": "OpenImageIO2.5", "build_type": "rpm"},
        ],
    )
    ranges = [
        {
            "source_component": "OpenImageIO",
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"fixed": "3.1.11.0"},
                        {"introduced": "0"},
                        {"fixed": "3.0.16.0"},
                    ],
                }
            ],
        }
    ]
    score, reason = score_manifest(golden, rows, ranges=ranges)
    assert score == 1.0
    assert reason is None


def test_score_soft_ranges_missing_fixed_fails():
    """Soft ranges fail when an expected fixed token is absent."""
    golden = load_goldens()["CVE-2026-50291"]
    rows = _seeded_rows(
        golden,
        [
            {"name": "OpenImageIO", "build_type": "rpm"},
            {"name": "OpenImageIO2.5", "build_type": "rpm"},
        ],
    )
    ranges = [
        {
            "source_component": "OpenImageIO",
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.16.0"}],
                }
            ],
        }
    ]
    score, reason = score_manifest(golden, rows, ranges=ranges)
    assert score == 0.0
    assert reason is not None
    assert "3.1.11.0" in reason


def test_score_empty_ranges_rejects_invented_entry():
    """An empty golden ranges list rejects any produced range entry."""
    golden = load_goldens()["CVE-2026-18090"]
    score, reason = score_manifest(
        golden,
        _seeded_rows(golden, [{"name": "gdk-pixbuf2", "build_type": "rpm"}]),
        ranges=[
            {
                "source_component": "gdk-pixbuf",
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
            }
        ],
    )
    assert score == 0.0
    assert reason is not None
    assert "expected no ranges" in reason


def test_score_osv_tokens_differ_from_advisory_wording():
    """OSV SEMVER soft tokens pass even when they differ from advisory shorthand."""
    golden = {
        "seed": "postgresql",
        "required": [
            {
                "name": "postgresql",
                "build_type": "rpm",
                "source_component": "postgresql",
            }
        ],
        "allow_extra_same_project": True,
        "require_full_path": False,
        # Advisory text may say "18.5"; OSV SEMVER uses "18.5.0".
        "ranges": [
            {
                "source_component": "postgresql",
                "fixed": ["18.5.0", "17.11.0"],
            }
        ],
    }
    score, reason = score_manifest(
        golden,
        [{"name": "postgresql", "build_type": "rpm", "source_component": "postgresql"}],
        ranges=[
            {
                "source_component": "postgresql",
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "18.5.0"},
                            {"introduced": "17.0.0"},
                            {"fixed": "17.11.0"},
                        ],
                    }
                ],
            }
        ],
    )
    assert score == 1.0
    assert reason is None


def test_cached_flaws_have_seed_fields():
    """Each locked CVE cache entry can seed the feature."""
    missing = []
    thin = []
    no_upstream = []
    for cve_id in DEFAULT_CVE_IDS:
        cached = read_cache_json(cve_id)
        if not cached:
            missing.append(cve_id)
            continue
        has_text = bool(cached.get("title")) and bool(
            cached.get("description") or cached.get("comment_zero")
        )
        if not has_text or "components" not in cached:
            thin.append(cve_id)
        if "upstream_data" not in cached:
            no_upstream.append(cve_id)
    assert not missing, f"missing OSIDB cache entries: {missing}"
    assert not thin, f"cache entries missing title, description, or components: {thin}"
    assert not no_upstream, f"cache entries missing upstream_data key: {no_upstream}"


@pytest.mark.asyncio(loop_scope="session")
async def test_eval_suggest_manifest_component_and_state(manifest_component_cases):
    """Live SuggestManifestComponentAndState eval against the configured catalogs."""
    cve_features = pytest.importorskip("aegis_ai.features.cve")
    feature_cls = getattr(cve_features, "SuggestManifestComponentAndState", None)
    if feature_cls is None:
        pytest.skip("SuggestManifestComponentAndState is not importable")
    if not manifest_component_cases:
        pytest.skip("No manifest-component cases selected")
    from aegis_ai.agents import rh_feature_agent

    await run_evaluation(
        manifest_component_cases,
        [
            FeatureMetricsEvaluator(),
            ToolsUsedEvaluator(),
            ManifestComponentEvaluator(),
        ],
        suggest_manifest_component_and_state,
        agent=rh_feature_agent,
    )
