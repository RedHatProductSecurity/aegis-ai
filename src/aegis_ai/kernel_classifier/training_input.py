from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from aegis_ai.kernel_classifier import is_kernel_component
from aegis_ai.kernel_vulns_repo import describe_git_error, sync_vulns_repo

__all__ = [
    "CVSS_ISSUER_PRIORITY",
    "LEGACY_PATCH_ID_FIELD",
    "PATCH_IDS_FIELD",
    "SUPPORTED_SEVERITIES",
    "LinuxVulnsResolver",
    "build_generation_report",
    "extract_cvss_fields",
    "extract_patch_ids",
    "load_cve_id_file",
    "load_flaw_export",
    "migrate_patch_schema",
    "migrate_patch_schema_records",
    "normalize_classifier_record",
    "normalize_patch_ids",
    "parse_flaw_export",
    "select_best_cvss_score",
    "split_records_by_severity",
    "write_json",
]

PATCH_IDS_FIELD = "patch_ids"
LEGACY_PATCH_ID_FIELD = "patch_id"
SUPPORTED_SEVERITIES = ("IMPORTANT", "MODERATE", "LOW")
CVSS_ISSUER_PRIORITY = ("RH", "NIST", "CVEORG", "OSV", "CISA")


def normalize_patch_ids(values: Any) -> list[str]:
    if values is None:
        return []

    if isinstance(values, str):
        candidates = [values]
    elif isinstance(values, Iterable):
        candidates = list(values)
    else:
        return []

    result: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        if not isinstance(value, str):
            continue
        patch_id = value.strip()
        if not patch_id or patch_id in seen:
            continue
        seen.add(patch_id)
        result.append(patch_id)
    return result


def extract_patch_ids(record: dict[str, Any]) -> list[str]:
    if PATCH_IDS_FIELD in record:
        return normalize_patch_ids(record.get(PATCH_IDS_FIELD))
    return normalize_patch_ids(record.get(LEGACY_PATCH_ID_FIELD))


def migrate_patch_schema(record: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(record)
    migrated[PATCH_IDS_FIELD] = extract_patch_ids(record)
    migrated.pop(LEGACY_PATCH_ID_FIELD, None)
    return migrated


def migrate_patch_schema_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [migrate_patch_schema(record) for record in records]


def parse_flaw_export(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        results = data.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
    raise ValueError("Expected a JSON array of flaws or an object with `results`.")


def load_flaw_export(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return parse_flaw_export(data)


def load_cve_id_file(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as f:
        raw = f.read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, list):
        candidates = data
    else:
        candidates = []
        for line in raw.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            candidates.append(value)

    result: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        if not isinstance(value, str):
            continue
        cve_id = value.strip()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        result.append(cve_id)
    return result


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def _parse_date_string(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        return ""
    value = raw.strip()
    if "T" in value:
        value = value.split("T", 1)[0]
    return value


def _derive_classification_bucket(created_date: str) -> str:
    if not created_date:
        return ""
    try:
        year = datetime.strptime(created_date, "%Y-%m-%d").year  # noqa: DTZ007
    except ValueError:
        return ""
    return "2024+" if year >= 2024 else "pre-2024"


def _normalize_cvss_version(raw_version: Any) -> str:
    if raw_version is None:
        return ""
    value = str(raw_version).strip().upper()
    if not value:
        return ""
    if value == "V3":
        return "CVSSV3"
    if value == "V2":
        return "CVSSV2"
    return value


def select_best_cvss_score(cvss_scores: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred = [
        score
        for score in cvss_scores
        if _normalize_cvss_version(score.get("cvss_version")) == "CVSSV3"
    ]
    if not preferred:
        preferred = [
            score
            for score in cvss_scores
            if _normalize_cvss_version(score.get("cvss_version"))
        ]
    if not preferred:
        return None
    for issuer in CVSS_ISSUER_PRIORITY:
        for score in preferred:
            if str(score.get("issuer", "")).upper() == issuer:
                return score
    return preferred[0]


def extract_cvss_fields(flaw: dict[str, Any]) -> dict[str, Any]:
    best = select_best_cvss_score(
        [score for score in flaw.get("cvss_scores", []) if isinstance(score, dict)]
    )
    if not best:
        return {
            "cvss_score": 0.0,
            "cvss_vector": "",
            "cvss_version": "",
        }
    score_value = best.get("score")
    try:
        cvss_score = float(score_value if score_value is not None else 0.0)
    except (TypeError, ValueError):
        cvss_score = 0.0
    return {
        "cvss_score": cvss_score,
        "cvss_vector": str(best.get("vector", "") or ""),
        "cvss_version": _normalize_cvss_version(best.get("cvss_version")),
    }


def normalize_classifier_record(
    flaw: dict[str, Any],
    *,
    resolved_patch_ids: list[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Normalize a raw flaw dict into a classifier-ready record.

    Returns ``(record, None)`` on success or ``(None, reason)`` when the
    flaw is rejected.  Callers should branch on the second element:
    a truthy *reason* always means the first element is ``None``.
    """
    cve_id = str(flaw.get("cve_id", "") or "").strip()
    if not cve_id:
        return None, "missing_cve_id"

    severity = str(flaw.get("impact") or flaw.get("severity") or "").strip().upper()
    if severity not in SUPPORTED_SEVERITIES:
        return None, "unsupported_severity"

    if not is_kernel_component(flaw.get("components")):
        return None, "non_kernel"

    created_date = _parse_date_string(
        flaw.get("created_dt") or flaw.get("created_date")
    )
    patch_ids = (
        normalize_patch_ids(resolved_patch_ids)
        if resolved_patch_ids is not None
        else extract_patch_ids(flaw)
    )
    normalized = {
        "cve_id": cve_id,
        "severity": severity,
        "created_date": created_date,
        "classification": _derive_classification_bucket(created_date),
        **extract_cvss_fields(flaw),
        PATCH_IDS_FIELD: patch_ids,
    }
    return normalized, None


def _ks_statistic(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    try:
        from scipy.stats import ks_2samp
    except ImportError:
        return 0.0
    return float(ks_2samp(a, b).statistic)


def _date_to_ordinal(date_str: str) -> float | None:
    if not date_str:
        return None
    try:
        return float(datetime.strptime(date_str, "%Y-%m-%d").toordinal())  # noqa: DTZ007
    except ValueError:
        return None


def _cvss_bucket(cvss_score: float | None) -> str:
    if not cvss_score:
        return "low"
    if cvss_score < 4.0:
        return "low"
    if cvss_score < 7.0:
        return "medium"
    return "high"


def _date_year_bucket(created_date: str) -> str:
    if not created_date:
        return "unknown"
    try:
        return str(datetime.strptime(created_date, "%Y-%m-%d").year)  # noqa: DTZ007
    except ValueError:
        return "unknown"


def _stratum_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record["severity"]),
        _cvss_bucket(float(record.get("cvss_score") or 0)),
        _date_year_bucket(record.get("created_date", "")),
    )


def _score_split(
    train: list[dict[str, Any]],
    test: list[dict[str, Any]],
    test_ratio: float,
) -> dict[str, Any]:
    """Measure split quality — lower ``score`` is better."""
    by_sev_train: dict[str, int] = Counter(str(r["severity"]) for r in train)
    by_sev_test: dict[str, int] = Counter(str(r["severity"]) for r in test)
    max_class_dev = 0.0
    for sev in SUPPORTED_SEVERITIES:
        total = by_sev_train.get(sev, 0) + by_sev_test.get(sev, 0)
        if total == 0:
            continue
        actual = by_sev_test.get(sev, 0) / total
        dev = abs(actual - test_ratio)
        max_class_dev = max(max_class_dev, dev)

    train_cvss = [float(r.get("cvss_score") or 0) for r in train]
    test_cvss = [float(r.get("cvss_score") or 0) for r in test]
    ks_cvss = _ks_statistic(train_cvss, test_cvss)

    train_dates = [
        d
        for r in train
        if (d := _date_to_ordinal(r.get("created_date", ""))) is not None
    ]
    test_dates = [
        d
        for r in test
        if (d := _date_to_ordinal(r.get("created_date", ""))) is not None
    ]
    ks_date = _ks_statistic(train_dates, test_dates)

    score = max_class_dev + ks_cvss + ks_date
    return {
        "score": round(score, 4),
        "max_class_deviation": round(max_class_dev, 4),
        "ks_cvss": round(ks_cvss, 4),
        "ks_date": round(ks_date, 4),
    }


def split_records_by_severity(
    records: list[dict[str, Any]],
    *,
    test_ratio: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if not 0.0 < test_ratio < 1.0:
        raise ValueError("test_ratio must be between 0 and 1.")

    by_stratum: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        key = _stratum_key(record)
        by_stratum.setdefault(key, []).append(record)

    train: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []
    threshold = int(test_ratio * 100)
    singleton_strata = 0
    records_in_singletons = 0

    for _key, group in sorted(by_stratum.items()):
        if len(group) == 1:
            train.extend(group)
            singleton_strata += 1
            records_in_singletons += len(group)
            continue

        for record in group:
            bucket = _hash_to_bucket(record["cve_id"], seed)
            if bucket < threshold:
                test.append(record)
            else:
                train.append(record)

    per_severity_input = Counter(str(r["severity"]) for r in records)
    per_severity_train = Counter(str(r["severity"]) for r in train)
    per_severity_test = Counter(str(r["severity"]) for r in test)
    per_severity: dict[str, dict[str, int]] = {}
    for sev in SUPPORTED_SEVERITIES:
        per_severity[sev] = {
            "input": per_severity_input.get(sev, 0),
            "train": per_severity_train.get(sev, 0),
            "test": per_severity_test.get(sev, 0),
        }

    total_strata = len(by_stratum)
    report: dict[str, Any] = {
        "seed": seed,
        "test_ratio": test_ratio,
        "per_severity": per_severity,
        "strata_summary": {
            "total_strata": total_strata,
            "singleton_strata": singleton_strata,
            "records_in_singletons": records_in_singletons,
            "effective_strata": total_strata - singleton_strata,
        },
    }

    train = sorted(train, key=lambda row: (row.get("created_date", ""), row["cve_id"]))
    test = sorted(test, key=lambda row: (row.get("created_date", ""), row["cve_id"]))
    report["quality"] = _score_split(train, test, test_ratio)
    return train, test, report


def _hash_to_bucket(cve_id: str, seed: int) -> int:
    """Map a CVE ID to a stable 0–99 bucket using the seed as salt."""
    digest = hashlib.sha256(f"{seed}:{cve_id}".encode()).hexdigest()
    return int(digest, 16) % 100


class LinuxVulnsResolver:
    def __init__(self, repo_path: Path, logger: logging.Logger | None = None):
        self.repo_path = repo_path
        self.logger = logger or logging.getLogger(__name__)

    def _cve_year(self, cve_id: str) -> str | None:
        parts = cve_id.split("-")
        if len(parts) < 3 or parts[0].upper() != "CVE" or not parts[1].isdigit():
            self.logger.warning(
                "Skipping malformed CVE ID for vulns lookup: %s", cve_id
            )
            return None
        return parts[1]

    def ensure_repo(self) -> None:
        self.logger.info("Setting up Linux security vulnerabilities repository...")
        repo_existed = self.repo_path.exists()
        try:
            synced = sync_vulns_repo(self.repo_path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(
                f"Failed to clone linux-security-vulns repo to "
                f"{self.repo_path}: {describe_git_error(exc)}"
            ) from exc
        if synced and repo_existed:
            self.logger.info("Security vulnerabilities repository updated successfully")
        elif synced:
            self.logger.info("Security vulnerabilities repository cloned successfully")

    def json_paths(self, cve_id: str) -> list[Path]:
        """Return candidate JSON file paths for *cve_id* in the vulns repo."""
        cve_year = self._cve_year(cve_id)
        if cve_year is None:
            return []
        return [
            self.repo_path / f"cve/published/{cve_year}/{cve_id}.json",
            self.repo_path / f"cve/{cve_year}/{cve_id}.json",
            self.repo_path / f"cve/rejected/{cve_year}/{cve_id}.json",
        ]

    @staticmethod
    def extract_commit_hash_from_url(url: str) -> str | None:
        if not url:
            return None

        try:
            parsed = urlparse(url)
        except ValueError:
            return None

        hostname = (parsed.hostname or "").lower()
        if hostname not in {"git.kernel.org", "github.com", "www.github.com"}:
            return None

        path_parts = [part for part in parsed.path.split("/") if part]
        for index, part in enumerate(path_parts[:-1]):
            if part in {"c", "commit"}:
                candidate = path_parts[index + 1]
                if re.fullmatch(r"[0-9a-fA-F]{40}", candidate):
                    return candidate.lower()
        return None

    @staticmethod
    def extract_commit_hash_from_text(text: str) -> str | None:
        if not text:
            return None
        matches = re.findall(r"\b[0-9a-fA-F]{40}\b", text)
        return matches[0].lower() if matches else None

    def resolve_patch_ids(self, cve_id: str) -> list[str]:
        commits: list[str] = []

        for json_path in self.json_paths(cve_id):
            if not json_path.exists():
                continue
            try:
                with json_path.open("r", encoding="utf-8") as f:
                    json_data = json.load(f)
            except Exception as exc:
                self.logger.error("Error parsing JSON for %s: %s", cve_id, exc)
                continue

            references = []
            if (
                "containers" in json_data
                and "cna" in json_data["containers"]
                and "references" in json_data["containers"]["cna"]
            ):
                references = json_data["containers"]["cna"]["references"]
            elif "references" in json_data:
                references = json_data["references"]

            for ref in references:
                if not isinstance(ref, dict):
                    continue
                commit_hash = self.extract_commit_hash_from_url(ref.get("url", ""))
                if commit_hash:
                    commits.append(commit_hash)

            for field in ("description", "problemDescription", "mitigation"):
                field_value = json_data.get(field)
                if isinstance(field_value, str):
                    commit_hash = self.extract_commit_hash_from_text(field_value)
                    if commit_hash:
                        commits.append(commit_hash)

        return normalize_patch_ids(commits)


def build_generation_report(
    *,
    raw_total: int,
    normalized_total: int,
    train_records: list[dict[str, Any]],
    test_records: list[dict[str, Any]],
    skipped_reasons: Counter[str],
    manual_review_cves: list[str],
    split_report: dict[str, Any],
) -> dict[str, Any]:
    def _severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
        return dict(Counter(str(row["severity"]) for row in rows))

    return {
        "raw_total": raw_total,
        "normalized_total": normalized_total,
        "train_count": len(train_records),
        "test_count": len(test_records),
        "input_severity_distribution": _severity_counts(train_records + test_records),
        "train_severity_distribution": _severity_counts(train_records),
        "test_severity_distribution": _severity_counts(test_records),
        "skipped_reasons": dict(skipped_reasons),
        "manual_review_cves": sorted(set(manual_review_cves)),
        "split_report": split_report,
    }
