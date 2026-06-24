#!/usr/bin/env python3

"""Fetch raw OSIDB flaws and generate classifier-ready train/test JSON files."""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import osidb_bindings
from aegis_ai.kernel_classifier.training_input import (
    LinuxVulnsResolver,
    build_generation_report,
    extract_patch_ids,
    load_cve_id_file,
    load_flaw_export,
    normalize_classifier_record,
    split_records_by_severity,
    write_json,
)

SCRIPT_DIR = Path(__file__).resolve().parent
CLASSIFIER_DIR = SCRIPT_DIR / "classifier" / "kernel-cve-impact-classifier"

# CRITICAL is excluded: too few kernel CVEs at that severity to form a
# meaningful training class, and their characteristics overlap with IMPORTANT.
FLAWS_WITH_IMPACT = ["IMPORTANT", "MODERATE", "LOW"]
FLAWS_WITH_STATES = ["DONE"]
FLAWS_FIELDS = [
    "cve_id",
    "uuid",
    "title",
    "cve_description",
    "created_dt",
    "impact",
    "cvss_scores",
    "components",
]
FLAWS_ORDER = ["-created_dt"]
KERNEL_COMPONENTS = ["kernel", "Linux kernel"]
# Initial fetch cap per severity; retry loop widens if needed to fill MAJORITY_RATIO.
DEFAULT_MAX_PER_IMPACT = 500
MINORITY_CLASS = "IMPORTANT"
MAJORITY_RATIO = 3
FETCH_MAX_RETRIES = 3

DATA_DIR = CLASSIFIER_DIR / "data"
DEFAULT_TRAIN_JSON = DATA_DIR / "train_kernel_cves.json"
DEFAULT_TEST_JSON = DATA_DIR / "test_kernel_cves.json"
DEFAULT_REPORT_JSON = DATA_DIR / "generation_report.json"
DEFAULT_VULNS_REPO = DATA_DIR / "linux_security_vulns"
OSIDB_URL = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")
DEFAULT_SPLIT_SEED = 42

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _read_previous_seed(report_path: Path | None) -> int | None:
    """Read the split seed from an existing generation report, or None."""
    if report_path is None or not report_path.exists():
        return None
    try:
        with report_path.open(encoding="utf-8") as f:
            data = json.load(f)
        seed = data.get("split_report", {}).get("seed")
        if isinstance(seed, int):
            logger.info("Reusing seed %d from %s", seed, report_path)
            return seed
    except (OSError, ValueError, KeyError):
        pass
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch raw OSIDB flaws or ingest a local flaw export, then generate "
            "classifier-ready train/test JSON files for the kernel classifier."
        )
    )
    parser.add_argument(
        "--input-flaws-json",
        type=Path,
        help="Path to a local JSON flaw export (array of flaws or object with results).",
    )
    parser.add_argument(
        "--cve-ids",
        type=Path,
        help="Path to a file of CVE IDs (JSON array or one per line) to fetch individually.",
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge fetched CVEs into existing output files instead of replacing them.",
    )
    parser.add_argument(
        "--train-output",
        type=Path,
        default=DEFAULT_TRAIN_JSON,
        help="Output path for train_kernel_cves.json.",
    )
    parser.add_argument(
        "--test-output",
        type=Path,
        default=DEFAULT_TEST_JSON,
        help="Output path for test_kernel_cves.json.",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=DEFAULT_REPORT_JSON,
        help="Output path for the generation report JSON.",
    )
    parser.add_argument(
        "--raw-output-json",
        type=Path,
        help="Optional path to write the raw flaw array used as generator input.",
    )
    parser.add_argument(
        "--raw-output-dir",
        type=Path,
        help="Optional directory to write one raw flaw JSON file per CVE.",
    )
    parser.add_argument(
        "--raw-only",
        action="store_true",
        help="Fetch/load flaws and write raw output only; skip train/test generation.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate and validate in memory, write only the report, and skip train/test output files.",
    )
    parser.add_argument(
        "--test-ratio",
        type=float,
        default=0.25,
        help="Fraction of normalized records to place in the test split.",
    )
    parser.add_argument(
        "--vulns-repo",
        type=Path,
        default=DEFAULT_VULNS_REPO,
        help="Path to the linux-security-vulns checkout used for patch resolution.",
    )
    parser.add_argument(
        "--skip-patch-resolution",
        action="store_true",
        help="Skip automatic patch resolution from linux-security-vulns.",
    )
    parser.add_argument(
        "--osidb-url",
        default=OSIDB_URL,
        help="OSIDB server URL for live fetches.",
    )
    parser.add_argument(
        "--impacts",
        nargs="+",
        default=FLAWS_WITH_IMPACT,
        help="Impact values to fetch from live OSIDB.",
    )
    parser.add_argument(
        "--states",
        nargs="+",
        default=FLAWS_WITH_STATES,
        help="Workflow states to fetch from live OSIDB.",
    )
    parser.add_argument(
        "--max-per-impact",
        type=int,
        default=DEFAULT_MAX_PER_IMPACT,
        help="Maximum number of flaws to fetch per impact level.",
    )
    parser.add_argument(
        "--owners",
        default=None,
        help=(
            "Comma-separated list of owner emails to filter by. "
            "When set, only flaws owned by these users are fetched from OSIDB."
        ),
    )
    args = parser.parse_args()
    if args.owners is not None:
        args.owners = [o.strip() for o in args.owners.split(",") if o.strip()]
    return args


def fetch_flaws_from_osidb(
    args: argparse.Namespace,
    *,
    max_per_impact: int | None = None,
    impacts: list[str] | None = None,
    owners: list[str] | None = None,
    session: Any | None = None,
) -> list[dict[str, Any]]:
    """Fetch raw flaws from OSIDB.

    *max_per_impact* caps the number of flaws requested per impact level
    per component/owner combination.  Defaults to ``args.max_per_impact``.

    *impacts* overrides ``args.impacts`` when provided, allowing the retry
    loop to target specific severity classes without mutating *args*.

    *owners* filters by flaw owner email.  Each owner is queried
    separately and results are deduplicated by UUID.

    *session* reuses an existing OSIDB session if provided.
    """
    per_impact_raw = (
        max_per_impact if max_per_impact is not None else args.max_per_impact
    )
    if per_impact_raw is None:
        raise ValueError(
            "max_per_impact must be set (via argument or args.max_per_impact)"
        )
    per_impact: int = per_impact_raw
    if session is None:
        logger.info("connecting OSIDB at %s", args.osidb_url)
        session = osidb_bindings.new_session(osidb_server_uri=args.osidb_url)
    flaws: list[dict[str, Any]] = []
    seen_uuids: set[str] = set()
    owner_list = owners or [None]
    for impact in impacts or args.impacts:
        for component in KERNEL_COMPONENTS:
            for owner in owner_list:
                owner_label = f"/{owner}" if owner else ""
                logger.info(
                    "retrieving up to %d %s/%s%s flaws in states %s",
                    per_impact,
                    impact,
                    component,
                    owner_label,
                    args.states,
                )
                owner_kwargs = {"owner": owner} if owner else {}
                flaw_iter = session.flaws.retrieve_list_iterator_async(
                    impact=impact,
                    workflow_state=args.states,
                    components=component,
                    max_results=per_impact,
                    include_fields=FLAWS_FIELDS,
                    order=FLAWS_ORDER,
                    owner_isempty="false",
                    **owner_kwargs,
                )
                for flaw in flaw_iter:
                    flaw_dict = flaw.to_dict()
                    uuid = flaw_dict.get("uuid")
                    if not uuid:
                        logger.info("skipping flaw without uuid")
                        continue
                    if not flaw_dict.get("cve_id"):
                        logger.info("skipping flaw without cve_id: %s", uuid)
                        continue
                    if uuid in seen_uuids:
                        continue
                    seen_uuids.add(uuid)
                    flaws.append(flaw_dict)
    logger.info("loaded %d raw flaws", len(flaws))
    return flaws


def _is_osidb_flaw_not_found(exc: BaseException) -> bool:
    response = getattr(exc, "response", None)
    if response is not None and getattr(response, "status_code", None) == 404:
        return True
    text = str(exc).lower()
    return "404" in text and ("not found" in text or "client error" in text)


def fetch_flaws_by_cve_ids(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.cve_ids is None:
        return []

    cve_ids = load_cve_id_file(args.cve_ids)
    logger.info("connecting OSIDB at %s", args.osidb_url)
    session = osidb_bindings.new_session(osidb_server_uri=args.osidb_url)

    flaws: list[dict[str, Any]] = []
    total = len(cve_ids)
    logger.info("retrieving %d flaws by explicit CVE ID", total)
    for index, cve_id in enumerate(cve_ids, start=1):
        logger.info("retrieving %d/%d: %s", index, total, cve_id)
        try:
            flaw = session.flaws.retrieve(
                id=cve_id,
                include_fields=FLAWS_FIELDS,
            )
        except Exception as exc:
            if _is_osidb_flaw_not_found(exc):
                logger.warning("No OSIDB flaw found for %s", cve_id)
                continue
            raise

        flaw_dict = flaw.to_dict()
        if not flaw_dict.get("cve_id"):
            logger.info("skipping flaw without cve_id: %s", flaw_dict.get("uuid"))
            continue
        flaws.append(flaw_dict)

    logger.info("loaded %d raw flaws", len(flaws))
    return flaws


def write_raw_flaw_dir(flaws: list[dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for flaw in flaws:
        cve_id = flaw.get("cve_id") or flaw.get("uuid")
        if not cve_id:
            continue
        target = output_dir / f"{cve_id}.json"
        suffix = 2
        while target.exists():
            target = output_dir / f"{cve_id}_{suffix}.json"
            suffix += 1
        if target.name != f"{cve_id}.json":
            logger.warning(
                'duplicate raw flaw for "%s"; writing to "%s" instead',
                cve_id,
                target.name,
            )
        write_json(target, flaw)


def normalize_flaws(
    flaws: list[dict[str, Any]],
    *,
    resolver: LinuxVulnsResolver | None,
    auto_resolve_patches: bool,
) -> tuple[list[dict[str, Any]], Counter[str], list[str], dict[str, str]]:
    normalized: list[dict[str, Any]] = []
    skipped = Counter()
    skipped_cves: dict[str, str] = {}
    manual_review_cves: list[str] = []
    seen_cves: set[str] = set()

    for flaw in flaws:
        cve_id = str(flaw.get("cve_id", "") or "").strip()
        if not cve_id:
            skipped["missing_cve_id"] += 1
            continue
        if cve_id in seen_cves:
            skipped["duplicate_cve_id"] += 1
            skipped_cves[cve_id] = "duplicate_cve_id"
            continue
        seen_cves.add(cve_id)

        resolved_patch_ids: list[str] | None = None
        explicit_patch_ids = extract_patch_ids(flaw)
        if explicit_patch_ids:
            resolved_patch_ids = explicit_patch_ids
        elif auto_resolve_patches and resolver is not None:
            resolved_patch_ids = resolver.resolve_patch_ids(cve_id)

        record, reason = normalize_classifier_record(
            flaw,
            resolved_patch_ids=resolved_patch_ids,
        )
        if reason:
            skipped[reason] += 1
            skipped_cves[cve_id] = reason
            continue

        if not record["patch_ids"]:
            manual_review_cves.append(cve_id)

        normalized.append(record)

    return normalized, skipped, manual_review_cves, skipped_cves


def print_report(report: dict[str, Any]) -> None:
    logger.info("generation summary:")
    logger.info("  raw flaws: %d", report["raw_total"])
    logger.info("  normalized candidates: %d", report["normalized_total"])
    logger.info("  train count: %d", report["train_count"])
    logger.info("  test count: %d", report["test_count"])
    if report["skipped_reasons"]:
        logger.info("  skipped reasons: %s", report["skipped_reasons"])
    if report["manual_review_cves"]:
        logger.info(
            "  manual review required for %d CVEs: %s",
            len(report["manual_review_cves"]),
            ", ".join(report["manual_review_cves"][:20]),
        )


def _load_existing_cve_ids(*paths: Path) -> set[str]:
    ids: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(records, list):
                ids.update(
                    r["cve_id"]
                    for r in records
                    if isinstance(r, dict) and "cve_id" in r
                )
        except Exception as exc:
            logger.warning("Could not read existing output file %s: %s", path, exc)
    return ids


def _load_existing_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not read existing output file %s: %s", path, exc)
        return []
    if not isinstance(records, list):
        logger.warning("Expected %s to contain a JSON list; ignoring it", path)
        return []
    return [record for record in records if isinstance(record, dict)]


def _merge_records(
    existing_train: list[dict[str, Any]],
    existing_test: list[dict[str, Any]],
    new_train: list[dict[str, Any]],
    new_test: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    new_train_ids = {record["cve_id"] for record in new_train}
    new_test_ids = {record["cve_id"] for record in new_test}

    merged_train = {
        record["cve_id"]: record
        for record in existing_train
        if "cve_id" in record and record["cve_id"] not in new_test_ids
    }
    merged_test = {
        record["cve_id"]: record
        for record in existing_test
        if "cve_id" in record and record["cve_id"] not in new_train_ids
    }

    for record in new_train:
        merged_train[record["cve_id"]] = record
        merged_test.pop(record["cve_id"], None)
    for record in new_test:
        merged_test[record["cve_id"]] = record
        merged_train.pop(record["cve_id"], None)

    train_records = sorted(
        merged_train.values(),
        key=lambda row: (row.get("created_date", ""), row["cve_id"]),
    )
    test_records = sorted(
        merged_test.values(),
        key=lambda row: (row.get("created_date", ""), row["cve_id"]),
    )
    return train_records, test_records


def _cap_per_class(
    records: list[dict[str, Any]],
    per_class_target: int,
    *,
    uncapped_classes: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Cap each severity class to *per_class_target*, keeping the newest CVEs.

    Classes listed in *uncapped_classes* are kept in full regardless of
    the target.
    """
    uncapped = uncapped_classes or set()
    by_severity: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_severity.setdefault(record.get("severity", ""), []).append(record)

    capped: list[dict[str, Any]] = []
    for severity, group in by_severity.items():
        if severity in uncapped or len(group) <= per_class_target:
            capped.extend(group)
            continue
        newest = sorted(
            group,
            key=lambda r: (r.get("created_date", ""), r["cve_id"]),
            reverse=True,
        )[:per_class_target]
        logger.info(
            "capped %s from %d to %d (keeping newest)",
            severity,
            len(group),
            per_class_target,
        )
        capped.extend(newest)
    return capped


def _warn_lost_cves(
    existing_ids: set[str],
    new_ids: set[str],
    skipped_cves: dict[str, str],
) -> int:
    lost = sorted(existing_ids - new_ids)
    for cve_id in lost:
        reason = skipped_cves.get(cve_id, "not returned by source")
        logger.warning("CVE %s will be removed from output: %s", cve_id, reason)
    return len(lost)


def main() -> int:
    args = parse_args()
    use_osidb = not args.cve_ids and not args.input_flaws_json

    if args.cve_ids:
        flaws = fetch_flaws_by_cve_ids(args)
    elif args.input_flaws_json:
        flaws = load_flaw_export(args.input_flaws_json)
    else:
        flaws = fetch_flaws_from_osidb(args, owners=args.owners)

    if args.raw_output_json:
        write_json(args.raw_output_json, flaws)
    if args.raw_output_dir:
        write_raw_flaw_dir(flaws, args.raw_output_dir)
    if args.raw_only:
        logger.info("raw-only mode complete")
        return 0

    resolver: LinuxVulnsResolver | None = None
    if not args.skip_patch_resolution:
        resolver = LinuxVulnsResolver(args.vulns_repo, logger=logger)
        resolver.ensure_repo()

    existing_ids = _load_existing_cve_ids(args.train_output, args.test_output)

    normalized, skipped, manual_review_cves, skipped_cves = normalize_flaws(
        flaws,
        resolver=resolver,
        auto_resolve_patches=not args.skip_patch_resolution,
    )

    per_class = Counter(str(r["severity"]) for r in normalized)
    minority_count = per_class.get(MINORITY_CLASS, 0)
    majority_classes = [imp for imp in args.impacts if imp != MINORITY_CLASS]

    if use_osidb:
        seen_cve_ids = {f.get("cve_id") for f in flaws if f.get("cve_id")}
        fetch_windows: dict[str, int] = {
            imp: args.max_per_impact for imp in args.impacts
        }
        survival_rates: dict[str, float] = {}
        osidb_session = osidb_bindings.new_session(osidb_server_uri=args.osidb_url)

        for retry in range(1, FETCH_MAX_RETRIES + 1):
            minority_count = per_class.get(MINORITY_CLASS, 0)
            majority_target = minority_count * MAJORITY_RATIO

            deficient = [MINORITY_CLASS] if minority_count < args.max_per_impact else []
            deficient += [
                imp
                for imp in majority_classes
                if per_class.get(imp, 0) < majority_target
            ]
            if not deficient:
                break

            made_progress = False
            for impact in deficient:
                target = (
                    args.max_per_impact if impact == MINORITY_CLASS else majority_target
                )
                shortfall = target - per_class.get(impact, 0)
                if shortfall <= 0:
                    continue
                rate = survival_rates.get(impact, 0.1)
                batch_size = math.ceil(shortfall / max(rate, 0.1))
                new_window = fetch_windows[impact] + batch_size
                logger.info(
                    "fetch retry %d/%d: %s has %d/%d; widening window to %d",
                    retry,
                    FETCH_MAX_RETRIES,
                    impact,
                    per_class.get(impact, 0),
                    target,
                    new_window,
                )
                extra_flaws = fetch_flaws_from_osidb(
                    args,
                    max_per_impact=new_window,
                    impacts=[impact],
                    owners=args.owners,
                    session=osidb_session,
                )
                new_flaws = [
                    f
                    for f in extra_flaws
                    if f.get("cve_id") and f["cve_id"] not in seen_cve_ids
                ]
                if not new_flaws:
                    logger.info("no new %s flaws available from OSIDB", impact)
                    continue
                made_progress = True
                fetch_windows[impact] = new_window
                seen_cve_ids.update(f["cve_id"] for f in new_flaws)
                flaws.extend(new_flaws)
                batch_norm, new_skipped, new_manual, new_skipped_cves = normalize_flaws(
                    new_flaws,
                    resolver=resolver,
                    auto_resolve_patches=not args.skip_patch_resolution,
                )
                batch_survived = len(batch_norm)
                if len(new_flaws):
                    survival_rates[impact] = batch_survived / len(new_flaws)
                normalized.extend(batch_norm)
                skipped += new_skipped
                manual_review_cves.extend(new_manual)
                skipped_cves.update(new_skipped_cves)
                per_class.update(str(r["severity"]) for r in batch_norm)

            if not made_progress:
                logger.info("no new flaws available from OSIDB for any deficient class")
                break

    minority_count = per_class.get(MINORITY_CLASS, 0)
    majority_cap = minority_count * MAJORITY_RATIO
    logger.info(
        "%s count: %d — capping majority classes to %d (%d×)",
        MINORITY_CLASS,
        minority_count,
        majority_cap,
        MAJORITY_RATIO,
    )
    normalized = _cap_per_class(
        normalized, majority_cap, uncapped_classes={MINORITY_CLASS}
    )

    seed = _read_previous_seed(args.report_output) or DEFAULT_SPLIT_SEED
    train_records, test_records, split_report = split_records_by_severity(
        normalized,
        test_ratio=args.test_ratio,
        seed=seed,
    )
    report = build_generation_report(
        raw_total=len(flaws),
        normalized_total=len(normalized),
        train_records=train_records,
        test_records=test_records,
        skipped_reasons=skipped,
        manual_review_cves=manual_review_cves,
        split_report=split_report,
    )

    if args.report_output:
        write_json(args.report_output, report)
    print_report(report)

    if args.merge:
        existing_train_records = _load_existing_records(args.train_output)
        existing_test_records = _load_existing_records(args.test_output)
        train_records, test_records = _merge_records(
            existing_train_records,
            existing_test_records,
            train_records,
            test_records,
        )

    new_ids = {r["cve_id"] for r in train_records + test_records}
    lost_count = _warn_lost_cves(existing_ids, new_ids, skipped_cves)

    if args.dry_run:
        logger.info("dry-run complete; train/test JSON files were not written")
        return 0

    if not train_records and not test_records and existing_ids:
        logger.error(
            "Refusing to overwrite non-empty output files with 0 records "
            "(%d existing CVEs would be lost). "
            "Fix the source, use --input-flaws-json, or pass --dry-run to inspect.",
            len(existing_ids),
        )
        return 1

    if lost_count:
        logger.warning(
            "%d CVE(s) present in the existing files will not appear in the new output; "
            "see warnings above for per-CVE reasons.",
            lost_count,
        )

    write_json(args.train_output, train_records)
    write_json(args.test_output, test_records)
    logger.info('wrote train split to "%s"', args.train_output)
    logger.info('wrote test split to "%s"', args.test_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
