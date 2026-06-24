from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from aegis_ai.kernel_classifier.training_input import load_cve_id_file
from aegis_ai_ml.src.osidb_retrieve import (
    _cap_per_class,
    _load_existing_cve_ids,
    _merge_records,
    _warn_lost_cves,
    main,
    normalize_flaws,
)


# ---------------------------------------------------------------------------
# normalize_flaws — per-CVE skip reasons
# ---------------------------------------------------------------------------


def _kernel_flaw(cve_id: str, impact: str = "IMPORTANT") -> dict:
    return {
        "cve_id": cve_id,
        "impact": impact,
        "created_dt": "2025-01-01T00:00:00Z",
        "components": ["kernel"],
        "cvss_scores": [],
    }


def _non_kernel_flaw(cve_id: str) -> dict:
    return {
        "cve_id": cve_id,
        "impact": "IMPORTANT",
        "created_dt": "2025-01-01T00:00:00Z",
        "components": ["openssl"],
        "cvss_scores": [],
    }


def test_normalize_flaws_records_per_cve_skip_reason_non_kernel() -> None:
    flaws = [_non_kernel_flaw("CVE-2025-0001")]

    _, skipped, _, skipped_cves = normalize_flaws(
        flaws, resolver=None, auto_resolve_patches=False
    )

    assert skipped_cves["CVE-2025-0001"] == "non_kernel"
    assert skipped["non_kernel"] == 1


def test_normalize_flaws_records_per_cve_skip_reason_unsupported_severity() -> None:
    flaw = {
        "cve_id": "CVE-2025-0002",
        "impact": "CRITICAL",
        "created_dt": "2025-01-01T00:00:00Z",
        "components": ["kernel"],
        "cvss_scores": [],
    }

    _, _, _, skipped_cves = normalize_flaws(
        [flaw], resolver=None, auto_resolve_patches=False
    )

    assert skipped_cves["CVE-2025-0002"] == "unsupported_severity"


def test_normalize_flaws_records_per_cve_skip_reason_duplicate() -> None:
    flaw = _kernel_flaw("CVE-2025-0003")

    _, skipped, _, skipped_cves = normalize_flaws(
        [flaw, flaw], resolver=None, auto_resolve_patches=False
    )

    assert skipped_cves["CVE-2025-0003"] == "duplicate_cve_id"
    assert skipped["duplicate_cve_id"] == 1


def test_normalize_flaws_accepted_records_not_in_skipped_cves() -> None:
    flaw = _kernel_flaw("CVE-2025-0004")

    normalized, _, _, skipped_cves = normalize_flaws(
        [flaw], resolver=None, auto_resolve_patches=False
    )

    assert len(normalized) == 1
    assert "CVE-2025-0004" not in skipped_cves


# ---------------------------------------------------------------------------
# load_cve_id_file
# ---------------------------------------------------------------------------


def test_load_cve_id_file_json_array(tmp_path: Path) -> None:
    cve_ids_path = tmp_path / "cves.json"
    cve_ids_path.write_text(
        json.dumps(
            [
                "CVE-2025-0001",
                "CVE-2025-0002",
                "CVE-2025-0001",
                "  CVE-2025-0003  ",
            ]
        )
    )

    cve_ids = load_cve_id_file(cve_ids_path)

    assert cve_ids == ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"]


def test_load_cve_id_file_text_lines(tmp_path: Path) -> None:
    cve_ids_path = tmp_path / "cves.txt"
    cve_ids_path.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "CVE-2025-1000",
                "  CVE-2025-1001  ",
                "CVE-2025-1000",
            ]
        )
    )

    cve_ids = load_cve_id_file(cve_ids_path)

    assert cve_ids == ["CVE-2025-1000", "CVE-2025-1001"]


# ---------------------------------------------------------------------------
# _load_existing_cve_ids
# ---------------------------------------------------------------------------


def test_load_existing_cve_ids_reads_multiple_files(tmp_path: Path) -> None:
    train = tmp_path / "train.json"
    test = tmp_path / "test.json"
    train.write_text(
        json.dumps([{"cve_id": "CVE-2025-0001"}, {"cve_id": "CVE-2025-0002"}])
    )
    test.write_text(json.dumps([{"cve_id": "CVE-2025-0003"}]))

    ids = _load_existing_cve_ids(train, test)

    assert ids == {"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"}


def test_load_existing_cve_ids_returns_empty_for_missing_files(tmp_path: Path) -> None:
    ids = _load_existing_cve_ids(tmp_path / "nonexistent.json")

    assert ids == set()


def test_load_existing_cve_ids_tolerates_malformed_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("NOT JSON")

    with caplog.at_level(logging.WARNING):
        ids = _load_existing_cve_ids(bad)

    assert ids == set()
    assert "Could not read existing output file" in caplog.text


# ---------------------------------------------------------------------------
# _warn_lost_cves
# ---------------------------------------------------------------------------


def test_warn_lost_cves_logs_reason_from_skipped_cves(
    caplog: pytest.LogCaptureFixture,
) -> None:
    existing = {"CVE-2025-0001", "CVE-2025-0002"}
    new_ids = {"CVE-2025-0001"}
    skipped_cves = {"CVE-2025-0002": "non_kernel"}

    with caplog.at_level(logging.WARNING):
        lost = _warn_lost_cves(existing, new_ids, skipped_cves)

    assert lost == 1
    assert "CVE-2025-0002" in caplog.text
    assert "non_kernel" in caplog.text


def test_warn_lost_cves_uses_fallback_reason_when_not_in_skipped_cves(
    caplog: pytest.LogCaptureFixture,
) -> None:
    existing = {"CVE-2025-0010"}
    new_ids: set[str] = set()
    skipped_cves: dict[str, str] = {}

    with caplog.at_level(logging.WARNING):
        lost = _warn_lost_cves(existing, new_ids, skipped_cves)

    assert lost == 1
    assert "CVE-2025-0010" in caplog.text
    assert "not returned by source" in caplog.text


def test_warn_lost_cves_returns_zero_when_no_cves_lost() -> None:
    existing = {"CVE-2025-0001"}
    new_ids = {"CVE-2025-0001", "CVE-2025-0002"}

    lost = _warn_lost_cves(existing, new_ids, {})

    assert lost == 0


# ---------------------------------------------------------------------------
# _merge_records
# ---------------------------------------------------------------------------


def test_merge_records_updates_existing_and_adds_new() -> None:
    existing_train = [
        {"cve_id": "CVE-2025-0001", "created_date": "2025-01-01", "severity": "LOW"},
        {
            "cve_id": "CVE-2025-0002",
            "created_date": "2025-01-02",
            "severity": "MODERATE",
        },
    ]
    existing_test = [
        {
            "cve_id": "CVE-2025-0003",
            "created_date": "2025-01-03",
            "severity": "IMPORTANT",
        }
    ]
    new_train = [
        {
            "cve_id": "CVE-2025-0002",
            "created_date": "2025-02-02",
            "severity": "IMPORTANT",
        },
        {"cve_id": "CVE-2025-0004", "created_date": "2025-01-04", "severity": "LOW"},
    ]
    new_test = [
        {
            "cve_id": "CVE-2025-0001",
            "created_date": "2025-02-01",
            "severity": "MODERATE",
        }
    ]

    merged_train, merged_test = _merge_records(
        existing_train,
        existing_test,
        new_train,
        new_test,
    )

    assert [record["cve_id"] for record in merged_train] == [
        "CVE-2025-0004",
        "CVE-2025-0002",
    ]
    assert [record["cve_id"] for record in merged_test] == [
        "CVE-2025-0003",
        "CVE-2025-0001",
    ]
    assert (
        next(record for record in merged_train if record["cve_id"] == "CVE-2025-0002")[
            "severity"
        ]
        == "IMPORTANT"
    )
    assert (
        next(record for record in merged_test if record["cve_id"] == "CVE-2025-0001")[
            "severity"
        ]
        == "MODERATE"
    )


# ---------------------------------------------------------------------------
# Incremental normalization equivalence
# ---------------------------------------------------------------------------


def test_incremental_normalization_matches_full_pass() -> None:
    """Normalizing in two batches produces the same result as one full pass."""
    batch_1 = [
        _kernel_flaw("CVE-2025-0010", "IMPORTANT"),
        _kernel_flaw("CVE-2025-0011", "MODERATE"),
        _non_kernel_flaw("CVE-2025-0012"),
    ]
    batch_2 = [
        _kernel_flaw("CVE-2025-0013", "LOW"),
        _kernel_flaw("CVE-2025-0014", "IMPORTANT"),
        _kernel_flaw("CVE-2025-0010", "IMPORTANT"),  # duplicate
    ]

    full_normalized, full_skipped, full_manual, full_skipped_cves = normalize_flaws(
        batch_1 + batch_2, resolver=None, auto_resolve_patches=False
    )

    inc_norm_1, inc_skip_1, inc_manual_1, inc_skip_cves_1 = normalize_flaws(
        batch_1, resolver=None, auto_resolve_patches=False
    )
    seen_cve_ids = {r["cve_id"] for r in inc_norm_1} | set(inc_skip_cves_1)
    deduped_batch_2 = [
        f for f in batch_2 if f.get("cve_id") and f["cve_id"] not in seen_cve_ids
    ]
    inc_norm_2, inc_skip_2, inc_manual_2, inc_skip_cves_2 = normalize_flaws(
        deduped_batch_2, resolver=None, auto_resolve_patches=False
    )

    combined_normalized = inc_norm_1 + inc_norm_2
    combined_skipped = inc_skip_1 + inc_skip_2
    combined_manual = inc_manual_1 + inc_manual_2

    assert {r["cve_id"] for r in combined_normalized} == {
        r["cve_id"] for r in full_normalized
    }
    assert set(combined_manual) == set(full_manual)
    assert combined_skipped["non_kernel"] == full_skipped["non_kernel"]


# ---------------------------------------------------------------------------
# main() retry loop — offset calculation, dedup, and early exit
# ---------------------------------------------------------------------------


def _make_kernel_flaws(
    prefix: str, start: int, count: int, impact: str = "IMPORTANT"
) -> list[dict[str, Any]]:
    """Generate a batch of valid kernel flaws."""
    return [
        {
            "cve_id": f"CVE-2025-{prefix}{i:04d}",
            "impact": impact,
            "created_dt": f"2025-01-{(i % 28) + 1:02d}T00:00:00Z",
            "components": ["kernel"],
            "cvss_scores": [],
        }
        for i in range(start, start + count)
    ]


class TestMainRetryLoop:
    """Exercise the retry loop in main() to verify offset progression,
    survival-rate heuristic, and early exit on empty batch."""

    @pytest.fixture()
    def output_dir(self, tmp_path: Path) -> Path:
        train = tmp_path / "train.json"
        test = tmp_path / "test.json"
        train.write_text("[]")
        test.write_text("[]")
        return tmp_path

    def _run_main(
        self,
        tmp_path: Path,
        fetch_side_effect: list[list[dict[str, Any]]],
    ) -> int:
        """Run main() with mocked fetch and file outputs in tmp_path."""
        train_out = tmp_path / "train.json"
        test_out = tmp_path / "test.json"
        report_out = tmp_path / "report.json"
        train_out.write_text("[]")
        test_out.write_text("[]")

        argv = [
            "osidb_retrieve.py",
            "--train-output",
            str(train_out),
            "--test-output",
            str(test_out),
            "--report-output",
            str(report_out),
            "--skip-patch-resolution",
            "--osidb-url",
            "https://fake.example",
            "--impacts",
            "IMPORTANT",
        ]

        call_count = {"n": 0}

        def mock_fetch(
            args,
            *,
            max_per_impact=None,
            impacts=None,
            owners=None,
            session=None,
        ):
            idx = call_count["n"]
            call_count["n"] += 1
            if idx < len(fetch_side_effect):
                return fetch_side_effect[idx]
            return []

        with (
            patch("sys.argv", argv),
            patch(
                "aegis_ai_ml.src.osidb_retrieve.fetch_flaws_from_osidb",
                side_effect=mock_fetch,
            ),
            patch(
                "aegis_ai_ml.src.osidb_retrieve.osidb_bindings",
            ),
        ):
            return main()

    def test_retry_fetches_more_when_initial_batch_insufficient(
        self,
        tmp_path: Path,
    ) -> None:
        initial_batch = _make_kernel_flaws("A", 1, 3)
        retry_batch = _make_kernel_flaws("B", 1, 10)

        rc = self._run_main(tmp_path, [initial_batch, retry_batch])

        assert rc == 0
        train = json.loads((tmp_path / "train.json").read_text())
        test = json.loads((tmp_path / "test.json").read_text())
        all_ids = {r["cve_id"] for r in train + test}
        assert len(all_ids) >= 10

    def test_retry_exits_early_when_no_new_flaws(self, tmp_path: Path) -> None:
        initial_batch = _make_kernel_flaws("A", 1, 3)

        rc = self._run_main(tmp_path, [initial_batch, []])

        assert rc == 0
        train = json.loads((tmp_path / "train.json").read_text())
        test = json.loads((tmp_path / "test.json").read_text())
        all_ids = {r["cve_id"] for r in train + test}
        assert len(all_ids) == 3

    def test_retry_deduplicates_across_batches(self, tmp_path: Path) -> None:
        initial_batch = _make_kernel_flaws("A", 1, 3)
        # Second batch has overlap with first + some new
        retry_batch = initial_batch[:2] + _make_kernel_flaws("B", 1, 8)

        rc = self._run_main(tmp_path, [initial_batch, retry_batch])

        assert rc == 0
        train = json.loads((tmp_path / "train.json").read_text())
        test = json.loads((tmp_path / "test.json").read_text())
        all_ids = {r["cve_id"] for r in train + test}
        # Should not count duplicates toward total
        assert len(all_ids) == len(set(all_ids))
        assert len(all_ids) >= 10

    def test_no_retry_when_initial_batch_sufficient(self, tmp_path: Path) -> None:
        initial_batch = _make_kernel_flaws("A", 1, 12)

        rc = self._run_main(tmp_path, [initial_batch])

        assert rc == 0
        train = json.loads((tmp_path / "train.json").read_text())
        test = json.loads((tmp_path / "test.json").read_text())
        all_ids = {r["cve_id"] for r in train + test}
        assert len(all_ids) == 12


# ---------------------------------------------------------------------------
# _cap_per_class
# ---------------------------------------------------------------------------


def _record(cve_id: str, severity: str, created_date: str) -> dict:
    return {"cve_id": cve_id, "severity": severity, "created_date": created_date}


def test_cap_per_class_noop_when_under_target() -> None:
    records = [
        _record("CVE-0001", "IMPORTANT", "2024-01-01"),
        _record("CVE-0002", "MODERATE", "2024-02-01"),
        _record("CVE-0003", "LOW", "2024-03-01"),
    ]

    capped = _cap_per_class(records, per_class_target=5)

    assert len(capped) == 3


def test_cap_per_class_trims_overrepresented_classes() -> None:
    records = (
        [_record(f"CVE-I-{i}", "IMPORTANT", f"2024-0{i + 1}-01") for i in range(3)]
        + [_record(f"CVE-M-{i}", "MODERATE", f"2024-0{i + 1}-01") for i in range(10)]
        + [_record(f"CVE-L-{i}", "LOW", f"2024-0{i + 1}-01") for i in range(10)]
    )

    capped = _cap_per_class(records, per_class_target=5)

    sev_counts = Counter(r["severity"] for r in capped)
    assert sev_counts["IMPORTANT"] == 3
    assert sev_counts["MODERATE"] == 5
    assert sev_counts["LOW"] == 5


def test_cap_per_class_keeps_newest_cves() -> None:
    records = [
        _record("CVE-OLD", "IMPORTANT", "2020-01-01"),
        _record("CVE-MID", "IMPORTANT", "2022-01-01"),
        _record("CVE-NEW", "IMPORTANT", "2024-01-01"),
    ]

    capped = _cap_per_class(records, per_class_target=2)

    capped_ids = {r["cve_id"] for r in capped}
    assert "CVE-OLD" not in capped_ids
    assert "CVE-MID" in capped_ids
    assert "CVE-NEW" in capped_ids


# ---------------------------------------------------------------------------
# Multi-impact retry targets deficient classes
# ---------------------------------------------------------------------------


class TestMultiImpactRetryBalance:
    """Verify that the retry loop targets only under-represented severity
    classes and that the per-class cap prevents overshoot."""

    def _run_main_multi_impact(
        self,
        tmp_path: Path,
        fetch_side_effect: list[list[dict[str, Any]]],
    ) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
        train_out = tmp_path / "train.json"
        test_out = tmp_path / "test.json"
        report_out = tmp_path / "report.json"
        train_out.write_text("[]")
        test_out.write_text("[]")

        argv = [
            "osidb_retrieve.py",
            "--train-output",
            str(train_out),
            "--test-output",
            str(test_out),
            "--report-output",
            str(report_out),
            "--skip-patch-resolution",
            "--osidb-url",
            "https://fake.example",
            "--impacts",
            "IMPORTANT",
            "MODERATE",
            "LOW",
        ]

        call_count = {"n": 0}

        def mock_fetch(
            args,
            *,
            max_per_impact=None,
            impacts=None,
            owners=None,
            session=None,
        ):
            idx = call_count["n"]
            call_count["n"] += 1
            if idx < len(fetch_side_effect):
                return fetch_side_effect[idx]
            return []

        with (
            patch("sys.argv", argv),
            patch(
                "aegis_ai_ml.src.osidb_retrieve.fetch_flaws_from_osidb",
                side_effect=mock_fetch,
            ),
            patch(
                "aegis_ai_ml.src.osidb_retrieve.osidb_bindings",
            ),
        ):
            rc = main()

        train = json.loads(train_out.read_text())
        test = json.loads(test_out.read_text())
        return rc, train, test

    def test_imbalanced_initial_fetch_gets_capped(self, tmp_path: Path) -> None:
        """When initial fetch returns far more LOW/MODERATE than IMPORTANT,
        the per-class cap limits majority classes to MAJORITY_RATIO × minority."""
        initial_batch = (
            _make_kernel_flaws("I", 1, 2, impact="IMPORTANT")
            + _make_kernel_flaws("M", 1, 50, impact="MODERATE")
            + _make_kernel_flaws("L", 1, 50, impact="LOW")
        )

        rc, train, test = self._run_main_multi_impact(tmp_path, [initial_batch, []])

        assert rc == 0
        all_records = train + test
        sev_counts = Counter(r["severity"] for r in all_records)
        important_count = sev_counts.get("IMPORTANT", 0)
        majority_cap = important_count * 3
        assert sev_counts.get("MODERATE", 0) <= majority_cap
        assert sev_counts.get("LOW", 0) <= majority_cap
