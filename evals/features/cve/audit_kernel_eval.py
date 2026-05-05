"""Post-eval audit of the kernel suggest-impact pipeline.

Reads ``kernel_eval_results.json`` (produced by the kernel eval test) and
generates a structured diagnostic report that surfaces:

  1. **Escalation floor overrides** — cases where the XGBoost classifier's
     escalation floor changed the LLM's output, classified as *helpful*
     (moved closer to expected) or *harmful* (moved further away).
  2. **Low-confidence classifier overrides** — floor overrides driven by
     XGBoost predictions with < 60% confidence on benign feature sets.
  3. **Impact disagreements** — any case where the final predicted impact
     differs from the expected ground truth, with the full signal chain
     (LLM CVSS → CVSS-band impact → classifier label → final output).
  4. **CVSS anchoring risk** — flags cases where the LLM's CVSS vector
     matches the classifier's cascade CVSS exactly despite the RH vector
     being excluded, suggesting possible NVD/NIST anchoring.

Usage::

    uv run python evals/features/cve/audit_kernel_eval.py          # default path
    uv run python evals/features/cve/audit_kernel_eval.py FILE.json # custom path
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis_ai.features.cve.impact_mappings import SEVERITY_ORDER, score_to_band

ESCALATION_FEATURES = {
    "uaf",
    "kernel_panic",
    "kernel_panic_plus_uaf",
    "danger",
    "remote",
    "networking",
    "skb",
    "packet",
    "servertoclientfail",
}

DEFAULT_RESULTS = Path(__file__).resolve().parent / "kernel_eval_results.json"


def rank(label: str) -> int:
    return SEVERITY_ORDER.get(label.upper(), len(SEVERITY_ORDER))


def direction(predicted: str, expected: str) -> str:
    diff = rank(predicted) - rank(expected)
    if diff < 0:
        return "overestimation"
    if diff > 0:
        return "underestimation"
    return "match"


def audit(results_path: Path) -> dict:
    with open(results_path, encoding="utf-8") as f:
        data = json.load(f)

    cases = data.get("cases", [])
    report: dict = {
        "timestamp": data.get("timestamp"),
        "total_cases": len(cases),
        "summary": {},
        "escalation_floor_overrides": [],
        "low_confidence_overrides": [],
        "deescalation_overrides": [],
        "impact_mismatches": [],
        "cvss_anchoring_flags": [],
    }

    n_match = n_over = n_under = 0
    n_floor_helpful = n_floor_harmful = n_floor_neutral = 0
    n_deescalation = 0

    for case in cases:
        if "error" in case:
            continue
        cve_id = case["cve_id"]
        expected = case.get("expected_impact")
        predicted = case.get("predicted_impact")
        if not expected or not predicted:
            continue
        raw_cvss = case.get("predicted_cvss3_score")
        cvss_score = float(raw_cvss) if raw_cvss is not None else 0.0
        cvss_vector = case.get("predicted_cvss3_vector", "")
        classifier = case.get("classifier") or {}

        clf_impact = classifier.get("impact")
        clf_confidence = classifier.get("confidence", 0.0)
        clf_probabilities = classifier.get("probabilities", {})
        clf_features = set(classifier.get("active_features", []))
        clf_cvss_vector = classifier.get("cvss_vector", "")
        floor_applied = classifier.get("escalation_floor_applied", False)

        llm_band = score_to_band(cvss_score) or ""

        d = direction(predicted, expected)
        if d == "match":
            n_match += 1
        elif d == "overestimation":
            n_over += 1
        else:
            n_under += 1

        # --- Escalation floor analysis ---
        if floor_applied and clf_impact:
            llm_distance = abs(rank(llm_band) - rank(expected))
            final_distance = abs(rank(predicted) - rank(expected))

            final_dir = direction(predicted, expected)
            if final_dir == "overestimation":
                effect = "overestimation"
            elif final_dir == "underestimation":
                llm_dir = direction(llm_band, expected)
                if llm_dir == "underestimation":
                    effect = "underestimation_unsafe"
                else:
                    effect = "underestimation_safe"
            else:
                effect = "match"

            if final_distance < llm_distance:
                n_floor_helpful += 1
            elif final_distance > llm_distance:
                n_floor_harmful += 1
            else:
                n_floor_neutral += 1

            override_entry = {
                "cve_id": cve_id,
                "expected": expected,
                "llm_cvss_band": llm_band,
                "classifier_label": clf_impact,
                "classifier_confidence": round(clf_confidence, 3),
                "classifier_probabilities": {
                    k: round(v, 4) for k, v in clf_probabilities.items()
                },
                "final_impact": predicted,
                "effect": effect,
                "active_features": sorted(clf_features),
            }
            report["escalation_floor_overrides"].append(override_entry)

            has_escalation_signals = bool(clf_features & ESCALATION_FEATURES)
            if clf_confidence < 0.6 and not has_escalation_signals:
                report["low_confidence_overrides"].append(
                    {
                        **override_entry,
                        "reason": (
                            f"classifier confidence {clf_confidence:.1%} on features "
                            f"{sorted(clf_features)} — none are escalation-worthy"
                        ),
                    }
                )

        # --- Impact mismatch ---
        if d != "match":
            report["impact_mismatches"].append(
                {
                    "cve_id": cve_id,
                    "expected": expected,
                    "predicted": predicted,
                    "direction": d,
                    "llm_cvss": cvss_score,
                    "llm_cvss_band": llm_band,
                    "classifier_label": clf_impact,
                    "classifier_confidence": round(clf_confidence, 3)
                    if clf_impact
                    else None,
                    "classifier_probabilities": (
                        {k: round(v, 4) for k, v in clf_probabilities.items()}
                        if clf_probabilities
                        else None
                    ),
                    "floor_applied": floor_applied,
                    "floor_caused_mismatch": (
                        floor_applied and direction(llm_band, expected) == "match"
                    ),
                }
            )

        # --- De-escalation override tracking ---
        deesc_rationale = case.get("deescalation_rationale")
        if deesc_rationale:
            n_deescalation += 1
            deesc_effect = direction(predicted, expected)
            report["deescalation_overrides"].append(
                {
                    "cve_id": cve_id,
                    "expected": expected,
                    "predicted": predicted,
                    "llm_cvss": cvss_score,
                    "llm_cvss_band": llm_band,
                    "classifier_label": clf_impact,
                    "effect": deesc_effect,
                    "rationale": deesc_rationale,
                }
            )

        # --- CVSS anchoring check ---
        if cvss_vector and clf_cvss_vector and cvss_vector == clf_cvss_vector:
            report["cvss_anchoring_flags"].append(
                {
                    "cve_id": cve_id,
                    "shared_vector": cvss_vector,
                    "note": (
                        "LLM vector matches cascade CVSS exactly; "
                        "check whether NVD CVSS was visible to the LLM"
                    ),
                }
            )

    report["summary"] = {
        "exact_matches": n_match,
        "overestimations": n_over,
        "underestimations": n_under,
        "escalation_floor_helpful": n_floor_helpful,
        "escalation_floor_harmful": n_floor_harmful,
        "escalation_floor_neutral": n_floor_neutral,
        "low_confidence_overrides": len(report["low_confidence_overrides"]),
        "deescalation_overrides": n_deescalation,
        "cvss_anchoring_flags": len(report["cvss_anchoring_flags"]),
    }

    return report


def print_report(report: dict) -> None:
    s = report["summary"]

    print("=" * 72)
    print("  KERNEL EVAL AUDIT REPORT")
    print(f"  Generated from eval run: {report['timestamp']}")
    print("=" * 72)

    print(f"\n  Total cases: {report['total_cases']}")
    print(f"  Exact matches:    {s['exact_matches']}")
    print(f"  Overestimations:  {s['overestimations']}")
    print(f"  Underestimations: {s['underestimations']}")

    # --- Escalation floor ---
    overrides = report["escalation_floor_overrides"]
    if overrides:
        print(f"\n{'─' * 72}")
        print(f"  ESCALATION FLOOR OVERRIDES ({len(overrides)} cases)")
        print(
            f"  Helpful: {s['escalation_floor_helpful']}  "
            f"Harmful: {s['escalation_floor_harmful']}  "
            f"Neutral: {s['escalation_floor_neutral']}"
        )
        print(f"{'─' * 72}")
        for o in overrides:
            marker = {
                "match": "=",
                "overestimation": "+",
                "underestimation_safe": "~",
                "underestimation_unsafe": "!",
            }[o["effect"]]
            print(
                f"  [{marker}] {o['cve_id']:20s}  "
                f"LLM={o['llm_cvss_band']:10s} → clf={o['classifier_label']:10s} "
                f"(conf={o['classifier_confidence']:.3f})  → final={o['final_impact']:10s}  "
                f"expected={o['expected']:10s}  [{o['effect']}]"
            )

    # --- Low-confidence overrides ---
    lco = report["low_confidence_overrides"]
    if lco:
        print(f"\n{'─' * 72}")
        print(f"  LOW-CONFIDENCE OVERRIDES ON BENIGN FEATURES ({len(lco)} cases)")
        print(f"{'─' * 72}")
        for o in lco:
            print(f"  {o['cve_id']}: {o['reason']}")
            print(
                f"    LLM band={o['llm_cvss_band']} → floor={o['classifier_label']} "
                f"→ final={o['final_impact']}  (expected={o['expected']})"
            )

    # --- De-escalation overrides ---
    deesc = report.get("deescalation_overrides", [])
    if deesc:
        print(f"\n{'─' * 72}")
        print(f"  DE-ESCALATION OVERRIDES ({len(deesc)} cases)")
        print(f"{'─' * 72}")
        for d in deesc:
            marker = (
                "="
                if d["effect"] == "match"
                else ("+" if d["effect"] == "overestimation" else "-")
            )
            print(
                f"  [{marker}] {d['cve_id']:20s}  "
                f"band={d['llm_cvss_band']:10s} → impact={d['predicted']:10s}  "
                f"expected={d['expected']:10s}  [{d['effect']}]"
            )
            rationale = d["rationale"]
            if len(rationale) > 80:
                rationale = rationale[:77] + "..."
            print(f"        rationale: {rationale}")

    # --- Impact mismatches ---
    mismatches = report["impact_mismatches"]
    if mismatches:
        print(f"\n{'─' * 72}")
        print(f"  IMPACT MISMATCHES ({len(mismatches)} cases)")
        print(f"{'─' * 72}")
        for m in mismatches:
            tag = "UNDER" if m["direction"] == "underestimation" else "OVER "
            floor_note = ""
            if m.get("floor_caused_mismatch"):
                floor_note = "  ← FLOOR CAUSED THIS"
            print(
                f"  [{tag}] {m['cve_id']:20s}  "
                f"predicted={m['predicted']:10s}  expected={m['expected']:10s}  "
                f"cvss={m['llm_cvss']:.1f} ({m['llm_cvss_band']})"
                f"{floor_note}"
            )

    # --- Anchoring flags ---
    anchoring = report["cvss_anchoring_flags"]
    if anchoring:
        print(f"\n{'─' * 72}")
        print(f"  CVSS ANCHORING FLAGS ({len(anchoring)} cases)")
        print(f"{'─' * 72}")
        for a in anchoring:
            print(f"  {a['cve_id']}: {a['shared_vector']}")
            print(f"    {a['note']}")

    print(f"\n{'=' * 72}")


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RESULTS
    if not path.exists():
        print(
            f"Results file not found: {path}\n"
            "Run the kernel eval first:\n"
            "  uv run pytest evals/features/cve/test_suggest_impact_kernel_cves.py -v",
            file=sys.stderr,
        )
        sys.exit(1)

    report = audit(path)
    print_report(report)

    audit_path = path.with_name("kernel_eval_audit.json")
    with open(audit_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Structured audit written to: {audit_path}")


if __name__ == "__main__":
    main()
