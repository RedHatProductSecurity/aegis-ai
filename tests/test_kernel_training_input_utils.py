from __future__ import annotations

import json
from collections import Counter

import pytest

from aegis_ai.kernel_classifier.training_input import (
    CVSS_ISSUER_PRIORITY,
    LinuxVulnsResolver,
    build_generation_report,
    is_kernel_flaw,
    migrate_patch_schema,
    normalize_classifier_record,
    split_records_by_severity,
)


def test_migrate_patch_schema_wraps_legacy_patch_id() -> None:
    record = {
        "cve_id": "CVE-2025-0001",
        "severity": "IMPORTANT",
        "patch_id": "deadbeef" * 5,
    }

    migrated = migrate_patch_schema(record)

    assert "patch_id" not in migrated
    assert migrated["patch_ids"] == ["deadbeef" * 5]


def test_normalize_classifier_record_prefers_rh_cvss() -> None:
    flaw = {
        "cve_id": "CVE-2025-0002",
        "impact": "MODERATE",
        "created_dt": "2024-06-01T00:00:00Z",
        "components": ["kernel"],
        "cvss_scores": [
            {"issuer": "NIST", "cvss_version": "V3", "vector": "NIST", "score": 5.0},
            {"issuer": "RH", "cvss_version": "V3", "vector": "RH", "score": 4.4},
        ],
    }

    record, reason = normalize_classifier_record(flaw, resolved_patch_ids=[])

    assert reason is None
    assert record is not None
    assert CVSS_ISSUER_PRIORITY[0] == "RH"
    assert record["cvss_vector"] == "RH"
    assert record["cvss_score"] == 4.4
    assert record["classification"] == "2024+"


def test_split_records_by_severity_is_deterministic_and_stratified() -> None:
    records = (
        [
            {
                "cve_id": f"CVE-2025-00{i:02d}",
                "severity": "IMPORTANT",
                "created_date": "2025-01-01",
            }
            for i in range(1, 5)
        ]
        + [
            {
                "cve_id": f"CVE-2025-10{i:02d}",
                "severity": "MODERATE",
                "created_date": "2025-01-01",
            }
            for i in range(1, 5)
        ]
        + [
            {
                "cve_id": f"CVE-2025-20{i:02d}",
                "severity": "LOW",
                "created_date": "2025-01-01",
            }
            for i in range(1, 5)
        ]
    )

    train_one, test_one, report_one = split_records_by_severity(
        records,
        test_ratio=0.25,
        seed=42,
    )
    train_two, test_two, report_two = split_records_by_severity(
        records,
        test_ratio=0.25,
        seed=42,
    )

    assert train_one == train_two
    assert test_one == test_two
    assert report_one == report_two
    assert report_one["per_severity"]["IMPORTANT"] == {
        "input": 4,
        "train": 2,
        "test": 2,
    }
    assert report_one["per_severity"]["MODERATE"] == {"input": 4, "train": 3, "test": 1}
    assert report_one["per_severity"]["LOW"] == {"input": 4, "train": 2, "test": 2}
    quality = report_one["quality"]
    assert set(quality) == {"score", "max_class_deviation", "ks_cvss", "ks_date"}
    assert all(isinstance(v, float) for v in quality.values())


def test_split_records_by_severity_handles_singletons_and_missing_severities() -> None:
    records = [
        {
            "cve_id": "CVE-2025-0001",
            "severity": "IMPORTANT",
            "created_date": "2025-01-01",
        },
        {
            "cve_id": "CVE-2025-0002",
            "severity": "LOW",
            "created_date": "2025-01-01",
        },
        {
            "cve_id": "CVE-2025-0003",
            "severity": "LOW",
            "created_date": "2025-01-01",
        },
    ]

    train, test, report = split_records_by_severity(records, test_ratio=0.25, seed=42)

    assert "CVE-2025-0001" in {row["cve_id"] for row in train}
    assert {row["cve_id"] for row in train + test} == {
        "CVE-2025-0001",
        "CVE-2025-0002",
        "CVE-2025-0003",
    }
    assert report["per_severity"]["IMPORTANT"] == {"input": 1, "train": 1, "test": 0}
    assert report["per_severity"]["MODERATE"] == {"input": 0, "train": 0, "test": 0}
    assert report["per_severity"]["LOW"] == {"input": 2, "train": 1, "test": 1}


def test_split_records_stratifies_across_cvss_and_date_dimensions() -> None:
    records = (
        [
            {
                "cve_id": f"CVE-2024-00{i:02d}",
                "severity": "IMPORTANT",
                "created_date": "2024-06-01",
                "cvss_score": 7.5,
            }
            for i in range(1, 11)
        ]
        + [
            {
                "cve_id": f"CVE-2025-10{i:02d}",
                "severity": "MODERATE",
                "created_date": "2025-03-01",
                "cvss_score": 5.5,
            }
            for i in range(1, 21)
        ]
        + [
            {
                "cve_id": f"CVE-2026-20{i:02d}",
                "severity": "LOW",
                "created_date": "2026-01-01",
                "cvss_score": 3.0,
            }
            for i in range(1, 21)
        ]
        + [
            {
                "cve_id": f"CVE-2025-30{i:02d}",
                "severity": "IMPORTANT",
                "created_date": "2025-09-01",
                "cvss_score": 5.0,
            }
            for i in range(1, 11)
        ]
    )

    train_a, test_a, report_a = split_records_by_severity(
        records,
        test_ratio=0.25,
        seed=42,
    )
    train_b, test_b, report_b = split_records_by_severity(
        records,
        test_ratio=0.25,
        seed=42,
    )

    assert train_a == train_b
    assert test_a == test_b
    assert report_a == report_b
    assert {r["cve_id"] for r in train_a + test_a} == {r["cve_id"] for r in records}

    strata = report_a["strata_summary"]
    assert strata["total_strata"] >= 4
    assert (
        strata["effective_strata"]
        == strata["total_strata"] - strata["singleton_strata"]
    )

    quality = report_a["quality"]
    assert set(quality) == {"score", "max_class_deviation", "ks_cvss", "ks_date"}
    assert all(isinstance(v, float) for v in quality.values())


def test_split_records_handles_missing_cvss_and_date() -> None:
    records = [
        {
            "cve_id": f"CVE-2025-00{i:02d}",
            "severity": "MODERATE",
            "created_date": "",
            "cvss_score": 0.0,
        }
        for i in range(1, 5)
    ]

    train, test, report = split_records_by_severity(records, test_ratio=0.25, seed=42)

    assert {r["cve_id"] for r in train + test} == {r["cve_id"] for r in records}
    assert report["per_severity"]["MODERATE"]["input"] == 4


def test_split_records_singleton_stratum_goes_to_train() -> None:
    records = [
        {
            "cve_id": "CVE-2024-0001",
            "severity": "IMPORTANT",
            "created_date": "2024-01-01",
            "cvss_score": 8.0,
        },
        {
            "cve_id": "CVE-2025-0001",
            "severity": "IMPORTANT",
            "created_date": "2025-01-01",
            "cvss_score": 5.0,
        },
        {
            "cve_id": "CVE-2025-0002",
            "severity": "IMPORTANT",
            "created_date": "2025-01-01",
            "cvss_score": 5.0,
        },
    ]

    train, test, _report = split_records_by_severity(records, test_ratio=0.25, seed=42)

    train_ids = {r["cve_id"] for r in train}
    assert "CVE-2024-0001" in train_ids
    assert _report["strata_summary"]["singleton_strata"] >= 1


@pytest.mark.parametrize("test_ratio", [0.0, -0.1, 1.0, 1.1])
def test_split_records_by_severity_rejects_invalid_ratio(test_ratio: float) -> None:
    with pytest.raises(ValueError, match="test_ratio must be between 0 and 1"):
        split_records_by_severity([], test_ratio=test_ratio, seed=42)


def test_build_generation_report_includes_manual_review_and_skips() -> None:
    train_records = [{"cve_id": "CVE-2025-0001", "severity": "IMPORTANT"}]
    test_records = [{"cve_id": "CVE-2025-0002", "severity": "LOW"}]

    report = build_generation_report(
        raw_total=5,
        normalized_total=2,
        train_records=train_records,
        test_records=test_records,
        skipped_reasons=Counter({"non_kernel": 2, "missing_cve_id": 1}),
        manual_review_cves=["CVE-2025-0002"],
        split_report={"seed": 42, "test_ratio": 0.25, "per_severity": {}},
    )

    assert report["raw_total"] == 5
    assert report["normalized_total"] == 2
    assert report["manual_review_cves"] == ["CVE-2025-0002"]
    assert report["skipped_reasons"] == {"non_kernel": 2, "missing_cve_id": 1}


def test_is_kernel_flaw_handles_list_and_string_components() -> None:
    assert is_kernel_flaw({"components": ["kernel"]})
    assert is_kernel_flaw({"components": ["Kernel"]})
    assert is_kernel_flaw({"components": ["openssl", "linux-kernel"]})
    assert is_kernel_flaw({"components": "kernel"})
    assert is_kernel_flaw({"components": "Linux Kernel"})
    assert not is_kernel_flaw({"components": ["openssl"]})
    assert not is_kernel_flaw({"components": "httpd"})
    assert not is_kernel_flaw({"components": []})
    assert not is_kernel_flaw({"components": None})


def test_extract_commit_hash_from_url_validates_hostname_and_path() -> None:
    commit_hash = "a" * 40

    assert (
        LinuxVulnsResolver.extract_commit_hash_from_url(
            f"https://git.kernel.org/stable/c/{commit_hash}"
        )
        == commit_hash
    )
    assert (
        LinuxVulnsResolver.extract_commit_hash_from_url(
            f"https://github.com/org/repo/commit/{commit_hash}"
        )
        == commit_hash
    )
    assert (
        LinuxVulnsResolver.extract_commit_hash_from_url(
            f"https://github.com/org/repo/commit/{'B' * 40}"
        )
        == "b" * 40
    )
    assert (
        LinuxVulnsResolver.extract_commit_hash_from_url(
            f"https://evil.example/github.com/commit/{commit_hash}"
        )
        is None
    )


def test_linux_vulns_resolver_resolve_patch_ids_normalizes_and_deduplicates(
    tmp_path,
) -> None:
    repo_path = tmp_path / "linux_security_vulns"
    published_dir = repo_path / "cve" / "published" / "2025"
    fallback_dir = repo_path / "cve" / "2025"
    published_dir.mkdir(parents=True)
    fallback_dir.mkdir(parents=True)

    hash_a = "A" * 40
    hash_b = "b" * 40
    hash_c = "C" * 40
    cve_id = "CVE-2025-0001"

    with (published_dir / f"{cve_id}.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "containers": {
                    "cna": {
                        "references": [
                            {"url": f"https://git.kernel.org/stable/c/{hash_a}"},
                            {"url": f"https://github.com/org/repo/commit/{hash_b}"},
                            {"url": f"https://evil.example/commit/{hash_c}"},
                        ]
                    }
                }
            },
            f,
        )

    with (fallback_dir / f"{cve_id}.json").open("w", encoding="utf-8") as f:
        json.dump(
            {
                "references": [
                    {"url": f"https://github.com/org/repo/commit/{hash_a.lower()}"}
                ],
                "mitigation": f"Backport references {hash_c}",
            },
            f,
        )

    resolver = LinuxVulnsResolver(repo_path)

    assert resolver.resolve_patch_ids(cve_id) == [
        hash_a.lower(),
        hash_b,
        hash_c.lower(),
    ]


def test_linux_vulns_resolver_resolve_patch_ids_skips_malformed_cve_id(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    resolver = LinuxVulnsResolver(tmp_path / "linux_security_vulns")
    commit_hash = "a" * 40

    with caplog.at_level("WARNING"):
        assert resolver.resolve_patch_ids("NOT-A-CVE") == []

    assert "Skipping malformed CVE ID for vulns lookup" in caplog.text
    assert (
        LinuxVulnsResolver.extract_commit_hash_from_url(
            f"https://notgithub.com/commit/{commit_hash}"
        )
        is None
    )
