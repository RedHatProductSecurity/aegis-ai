import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Literal, cast

import cvss
from pydantic import BaseModel, Field

import aegis_ai.toolsets.tools.osidb as osidb_tool
from aegis_ai import get_settings
from aegis_ai.data_models import CVEID
from aegis_ai.features import DeterministicFeature, DeterministicResult, Feature
from aegis_ai.features.cve.data_models import (
    CATEGORY_WEIGHTS,
    AffectedComponentEntry,
    CVEFeatureInput,
    CVSSDiffExplainerModel,
    PIIReportModel,
    QualityReviewModel,
    QueryAffectedComponentsModel,
    RevisedExplanationModel,
    SuggestAffectedComponentsModel,
    SuggestAffectedPackagesModel,
    SuggestCWEModel,
    SuggestDescriptionModel,
    SuggestImpactModel,
    SuggestStatementModel,
)
from aegis_ai.features.cve.impact_mappings import SEVERITY_ORDER, score_to_band
from aegis_ai.features.cve.kernel import (
    RULES_KERNEL,
    apply_afterpushed_llm_review,
    apply_deferred_low_review,
    apply_final_low_safety_invariant,
    apply_kpanic_cvss_override,
    apply_kpanic_llm_review,
    check_kernel_output,
    reconcile_kernel,
)
from aegis_ai.features.data_models import feature_deps
from aegis_ai.kernel_classifier import is_kernel_component
from aegis_ai.prompt import AegisPrompt
from aegis_ai.toolsets.tools.cwe import cwe_manager
from aegis_ai.toolsets.tools.kernel_cves import (
    get_cached_kernel_context_text,
)

logger = logging.getLogger(__name__)


# Inserted by A.Larkin (on 9 Sept 2026), dirty hack:
class KernelKpanicReviewModel(BaseModel):
    """Structured result of the NN+LLM-compatible KPANIC false-positive pass."""

    kernel_panic_supported: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_level: Literal[
        "demonstrated",
        "explicit",
        "strongly_implied",
        "speculative",
        "none",
    ]
    observed_failure: str
    additional_assumptions_required: list[str]
    independent_high_impact_strength: Literal[
        "strong",
        "moderate",
        "weak",
        "none",
    ]
    high_severity_still_supported_without_kpanic: bool
    # NEW51: machine-readable preservation profile.  Default NONE keeps the
    # parser fail-open compatible with an older/stochastic response that omits
    # the newly introduced field.
    preservation_profile: Literal[
        "NONE",
        "B1",
        "B2",
        "B3",
        "B4",
        "B5",
        "B6",
        "B7",
        "B8",
    ] = "NONE"
    independent_high_impact: list[str]
    previous_actionable_score_considered: bool
    previous_actionable_score_basis: list[str]
    allow_high_to_moderate7_downgrade: bool
    # NEW53: independent operational decision.  ``kernel_panic_supported`` is a
    # factual/evidence conclusion and MUST NOT by itself erase MODERATE7.  This
    # flag answers the separate policy question whether the extended
    # KPANIC/MODERATE7 review marker is no longer warranted and regular
    # MODERATE is safe.  Default False is intentionally fail-open.
    remove_operational_kpanic: bool = False
    # NEW56: independent safe-auto-close decision.  Defaults deliberately
    # fail closed so older/stochastic responses can never create LOW merely by
    # omitting the new fields.
    low_auto_close_supported: bool = False
    low_auto_close_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    low_auto_close_reason: str = ""
    # NEW57: third independent decision axis.  This is review routing, not
    # factual panic evidence and not an IMPORTANT-preservation verdict.
    # Defaults fail closed with respect to *creating* a new requirement: an
    # omitted field cannot unexpectedly preserve review on older responses.
    manual_review_still_required: bool = False
    manual_review_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    manual_review_reason: str = ""
    reason: str
    downgrade_reason: str


class KernelAfterPushedHighReviewModel(BaseModel):
    """Structured result of the NN+LLM request_llm_afterpushedtohigh() pass."""

    downgrade_to_moderate7: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_level: Literal[
        "demonstrated",
        "explicit",
        "strongly_implied",
        "speculative",
        "none",
    ]
    observed_vulnerability: str
    important_basis: str
    high_impact_demonstrated: bool
    high_impact_speculative: bool
    demonstrated_impact: dict[str, str]
    reachability: str
    required_privilege: str
    memory_corruption: str
    primitive_analysis: dict[str, bool]
    important_reducing_constraints: dict[str, bool]
    important_preserving_signals: dict[str, bool]
    decision_reason: str
    high_impact_demonstrated_reason: str
    downgrade_constraints_reason: str
    final_bucket: Literal["IMPORTANT retained", "MODERATE7"]


class KernelSecondOpinionModel(BaseModel):
    """Parsed result of the temporary Gemini ActionableScore experiment."""

    actionable_score: int
    actionable_score_lower: int | None = None

    primitive_class: Literal["NONE", "CLASS_A", "CLASS_B", "CLASS_C"]
    real_uaf: Literal["YES", "NO"]

    host_admin_required: Literal["YES", "NO", "UNKNOWN"]
    namespace_scoped_privilege: Literal["YES", "NO", "UNKNOWN"]

    important_candidate: Literal["YES", "NO"]
    manual_review: Literal["NO", "RECOMMENDED", "REQUIRED"]
    auto_downgrade_allowed: Literal["YES", "NO"]

    # A.Larkin second-opinion selected CVSS plumbing.
    # Optional by design: malformed/missing experimental CVSS must not discard
    # an otherwise useful ActionableScore result. kernel.py falls back to the
    # primary SuggestImpact CVSS when these are None.
    cvss_selected_score: float | None = None
    cvss_selected_vector: str | None = None

    final_bucket: str
    recommended_impact: Literal["MODERATE", "IMPORTANT"]

    raw_response: str


_ACTIONABLE_SCORE_PROMPT_PATH = Path(__file__).with_name("actionable_score_prompt.txt")
_KPANIC_PROMPT_PATH = Path(__file__).with_name("kpanic_prompt.txt")
_AFTERPUSHED_PROMPT_PATH = Path(__file__).with_name("afterpushedtohigh_prompt.txt")


async def _ensure_kernel_context_for_second_opinion(
    cve_id: str,
    deps,
    call_str: str,
) -> str:
    # ---------------------------------------------------------------------
    # A.Larkin kernel ActionableScore POC reliability fix.
    #
    # EXISTING AEGIS EAGER-PREFETCH PRECEDENT
    # ---------------------------------------
    # SuggestImpact.exec() already eagerly runs the kernel classifier before
    # the primary LLM turn:
    #
    #     # Eagerly run the kernel classifier so the result is available on
    #     # deps for both the tool fast-path and post-processing ...
    #     pre_clf = await kernel_impact_classify(...)
    #     deps.classifier_result = pre_clf
    #
    # That design intentionally prevents downstream correctness from depending
    # on whether an autonomous LLM happens to issue kernel_impact_tool.
    #
    # WHY THE SAME RELIABILITY GUARANTEE IS NEEDED HERE
    # -------------------------------------------------
    # RULES_KERNEL also explicitly tells the model:
    #
    #     "Always use kernel_cve tool if the component is the Linux kernel."
    #
    # However, kernel_cve_tool is exposed to the autonomous LLM through
    # kernel_extra_toolset. The application does not otherwise guarantee that
    # Gemini actually issues that tool call.
    #
    # CVE-2026-64457 demonstrated the failure mode:
    #
    #     primary Gemini omitted kernel_cve_tool
    #       -> kernel context cache remained empty
    #       -> ActionableScore was skipped
    #       -> AS1-AS7 compatibility rules could not run
    #
    # This is model tool-selection nondeterminism, not a CVE property.
    #
    # NEW BEHAVIOR
    # ------------
    # 1. Reuse the existing kernel_cve_tool cache first. This remains the
    #    normal zero-extra-work path when primary Gemini obeyed RULES_KERNEL.
    # 2. Only if the cache is empty, invoke the EXISTING kernel_cve_tool
    #    implementation deterministically at application level.
    # 3. Re-read the cache after the call.
    # 4. If the fallback itself fails, retain the existing POC fail-open
    #    behavior so normal SuggestImpact is never broken.
    #
    # This mirrors the PURPOSE of the existing eager kernel-classifier prefetch:
    # required downstream context should not disappear merely because the LLM
    # did not choose to call an available tool.
    #
    # IMPORTANT API CORRECTION
    # ------------------------
    # An earlier fallback version tried to infer arbitrary callable signatures
    # and, for two positional arguments, effectively called:
    #
    #     kernel_cve_tool(ctx, cve_id)
    #
    # Runtime diagnostics from this Aegis tree show the actual API:
    #
    #     kernel_cve_tool(
    #         ctx: RunContext[feature_deps],
    #         input: LINUXCVEToolInput,
    #     ) -> LINUXCVEToolResponse
    #
    # Therefore the second argument MUST be the structured Pydantic input:
    #
    #     LINUXCVEToolInput(cve_id=cve_id)
    #
    # Passing a bare string caused:
    #
    #     'str' object has no attribute 'cve_id'
    #
    # This version intentionally targets the real Aegis API rather than using
    # reflection-based guessing. It is simpler, clearer for upstream review,
    # and keeps kernel_cve_tool itself as the single source of truth.
    # ---------------------------------------------------------------------

    cached = get_cached_kernel_context_text(cve_id)
    if cached:
        return cached

    logger.warning(
        "%s: kernel_cve_tool cache missing after primary guarded_run(); "
        "primary LLM did not populate context required by ActionableScore. "
        "Using deterministic fallback analogous to the existing eager "
        "kernel-classifier prefetch.",
        call_str,
    )

    try:
        from types import SimpleNamespace

        from aegis_ai.toolsets.tools.kernel_cves import (
            LINUXCVEToolInput,
            kernel_cve_tool,
        )

        # -------------------------------------------------------------
        # A.Larkin deterministic kernel-context fallback API fix.
        #
        # kernel_cve_tool in this Aegis tree is a pydantic-ai Tool wrapper,
        # not a directly callable async function. The previous typed-input
        # fix correctly constructed:
        #
        #     LINUXCVEToolInput(cve_id=cve_id)
        #
        # but still attempted to call the Tool wrapper itself, producing:
        #
        #     'Tool' object is not callable
        #
        # The earlier diagnostic/reflection version had already shown that
        # the wrapper exposes the actual Python callable. Keep this simple
        # and explicit: unwrap only the known .function/.func attributes,
        # then call that underlying implementation with the structured input.
        #
        # This preserves the same design goal as the existing eager kernel
        # classifier prefetch: downstream correctness must not depend on
        # whether Gemini chooses to invoke an available tool.
        # -------------------------------------------------------------
        tool_func = getattr(kernel_cve_tool, "function", None) or getattr(
            kernel_cve_tool, "func", None
        )

        if tool_func is None:
            raise RuntimeError("kernel_cve_tool underlying callable not found")

        direct_ctx = SimpleNamespace(deps=deps)
        tool_input = LINUXCVEToolInput(cve_id=cve_id)

        logger.info(
            "%s: deterministic kernel_cve_tool fallback invoking "
            "underlying callable with "
            "LINUXCVEToolInput(cve_id=%s)",
            call_str,
            cve_id,
        )

        maybe_result = tool_func(direct_ctx, tool_input)

        if hasattr(maybe_result, "__await__"):
            maybe_result = await maybe_result

        cached = get_cached_kernel_context_text(cve_id)
        if cached:
            logger.info(
                "%s: deterministic kernel_cve_tool fallback populated "
                "kernel context (%d chars)",
                call_str,
                len(cached),
            )
            return cached

        logger.warning(
            "%s: deterministic kernel_cve_tool fallback completed but "
            "kernel context cache is still empty (response_type=%s)",
            call_str,
            type(maybe_result).__name__,
        )
        return ""

    except Exception as exc:
        logger.warning(
            "%s: deterministic kernel_cve_tool fallback failed: %s",
            call_str,
            exc,
        )
        return ""


def _load_actionable_score_prompt() -> str:
    return _ACTIONABLE_SCORE_PROMPT_PATH.read_text(encoding="utf-8")


def _load_kpanic_prompt() -> str:
    return _KPANIC_PROMPT_PATH.read_text(encoding="utf-8")


def _load_afterpushed_prompt() -> str:
    return _AFTERPUSHED_PROMPT_PATH.read_text(encoding="utf-8")


def _parse_afterpushed_review_response(
    text: str,
    call_str: str,
) -> KernelAfterPushedHighReviewModel:
    """Parse strict JSON from afterpushedtohigh_prompt.txt."""
    raw = text.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()

    if not raw.startswith("{") or not raw.endswith("}"):
        first = raw.find("{")
        last = raw.rfind("}")
        if first == -1 or last <= first:
            raise ValueError("AFTERPUSHED response does not contain a JSON object")
        raw = raw[first : last + 1]

    payload = json.loads(raw)
    review = KernelAfterPushedHighReviewModel.model_validate(payload)

    if review.downgrade_to_moderate7 and review.final_bucket != "MODERATE7":
        raise ValueError(
            "AFTERPUSHED semantic mismatch: downgrade=true but final_bucket is not MODERATE7"
        )
    if (
        not review.downgrade_to_moderate7
        and review.final_bucket != "IMPORTANT retained"
    ):
        raise ValueError(
            "AFTERPUSHED semantic mismatch: downgrade=false but final_bucket is not IMPORTANT retained"
        )

    logger.info(
        "%s: AFTERPUSHED_REVIEW parsed downgrade=%s confidence=%.2f "
        "evidence_level=%s high_impact_demonstrated=%s final_bucket=%s",
        call_str,
        review.downgrade_to_moderate7,
        review.confidence,
        review.evidence_level,
        review.high_impact_demonstrated,
        review.final_bucket,
    )
    return review


def _parse_kpanic_review_response(
    text: str,
    call_str: str,
) -> KernelKpanicReviewModel:
    """Parse the strict JSON contract from kpanic_prompt.txt.

    Failures are handled by the caller as fail-open: the pre-KPANIC-review
    reconciliation result remains unchanged.
    """
    raw = text.strip()

    # Be tolerant of an accidental Markdown fence even though the prompt
    # explicitly forbids it.
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()

    # Likewise tolerate a small amount of accidental prose by extracting the
    # outermost JSON object.  Pydantic still validates all required fields.
    if not raw.startswith("{") or not raw.endswith("}"):
        first = raw.find("{")
        last = raw.rfind("}")
        if first == -1 or last <= first:
            raise ValueError("KPANIC review response does not contain a JSON object")
        raw = raw[first : last + 1]

    payload = json.loads(raw)
    review = KernelKpanicReviewModel.model_validate(payload)

    if (
        review.independent_high_impact_strength == "strong"
        and not review.high_severity_still_supported_without_kpanic
    ):
        logger.warning(
            "%s: KPANIC review semantic inconsistency: strength=strong but "
            "high_severity_still_supported_without_kpanic=false",
            call_str,
        )

    logger.info(
        "%s: KPANIC_REVIEW parsed panic_supported=%s confidence=%.2f "
        "evidence_level=%s high_without_panic=%s strength=%s "
        "preservation_profile=%s allow_high_to_mod7=%s remove_operational_kpanic=%s "
        "low_auto_close=%s low_auto_close_confidence=%.2f "
        "manual_review_still_required=%s manual_review_confidence=%.2f",
        call_str,
        review.kernel_panic_supported,
        review.confidence,
        review.evidence_level,
        review.high_severity_still_supported_without_kpanic,
        review.independent_high_impact_strength,
        review.preservation_profile,
        review.allow_high_to_moderate7_downgrade,
        review.remove_operational_kpanic,
        review.low_auto_close_supported,
        review.low_auto_close_confidence,
        review.manual_review_still_required,
        review.manual_review_confidence,
    )
    return review


# Older version of this class before ActionableScore experiment:
# class KernelSecondOpinionModel(BaseModel):
#    """Temporary local experiment for kernel severity validation."""
#
#    recommended_impact: Literal["MODERATE", "IMPORTANT"]
#    useful_non_crash_primitive: bool
#    panic_dominant: bool
#    confidence: float = Field(ge=0.0, le=1.0)
#    primitive: str
#    rationale: str


# A.Larkin second-opinion selected CVSS plumbing.
def _parse_actionable_score_response(
    text: str,
    call_str: str,
) -> KernelSecondOpinionModel:
    def required(name: str) -> str:
        m = re.search(
            rf"(?m)^{re.escape(name)}=(.+?)\s*$",
            text,
        )
        if not m:
            raise ValueError(f"missing required field {name}")
        return m.group(1).strip()

    def optional(name: str) -> str | None:
        m = re.search(
            rf"(?m)^{re.escape(name)}=(.+?)\s*$",
            text,
        )
        return m.group(1).strip() if m else None

    score = int(required("ActionableScore"))

    lower_raw = optional("ActionableScoreLower")
    lower = int(lower_raw) if lower_raw is not None else None

    primitive_class = required("PrimitiveClass")
    real_uaf = required("RealUAF")
    host_admin = required("HostAdminRequired")
    namespace_priv = required("NamespaceScopedPrivilege")
    important_candidate = required("ImportantCandidate")
    manual_review = required("ManualReview")
    auto_downgrade = required("AutoDowngradeAllowed")

    # Parse the independently computed selected CVSS emitted AFTER the
    # ActionableScore section. Fail open: bad/missing experimental CVSS keeps
    # the ActionableScore result and reconciliation falls back to primary CVSS.
    cvss_selected_score: float | None = None
    cvss_selected_vector: str | None = None

    selected_score_raw = optional("CVSSSelectedScore")
    selected_vector_raw = optional("CVSSSelectedVector")

    if selected_score_raw is not None and selected_vector_raw is not None:
        try:
            selected_vector = selected_vector_raw.strip()
            selected_score_from_vector = cvss.CVSS3(selected_vector).scores()[0]
            selected_score_reported = float(selected_score_raw)

            if abs(selected_score_reported - selected_score_from_vector) > 1e-9:
                logger.info(
                    "%s: ACTIONABLE_SCORE selected CVSS score/vector mismatch "
                    "%.1f != %.1f; using vector-derived score",
                    call_str,
                    selected_score_reported,
                    selected_score_from_vector,
                )

            cvss_selected_score = float(selected_score_from_vector)
            cvss_selected_vector = selected_vector
        except Exception as exc:
            logger.warning(
                "%s: ACTIONABLE_SCORE selected CVSS invalid; "
                "falling back to primary CVSS for reconciliation: %s",
                call_str,
                exc,
            )
    elif selected_score_raw is not None or selected_vector_raw is not None:
        logger.warning(
            "%s: ACTIONABLE_SCORE selected CVSS incomplete "
            "(score_present=%s vector_present=%s); "
            "falling back to primary CVSS for reconciliation",
            call_str,
            selected_score_raw is not None,
            selected_vector_raw is not None,
        )

    # NEW49: tolerate the same documented bucket line when Gemini omits the
    # historical trailing "::" after Markdown bold.  Keep the parser narrow:
    # require the exact "Final recommended bucket:" label, require **...**,
    # and capture only the contents of that single line.  This fixes outputs
    # such as:
    #
    #   Final recommended bucket: **Borderline / manual review recommended**
    #
    # while preserving compatibility with the older:
    #
    #   Final recommended bucket: **Borderline / manual review recommended**::
    #
    # NEW49.1: also tolerate harmless leading indentation before the exact
    # label. Gemini sometimes emits the numbered-section body indented by spaces.
    # NEW49.2: Gemini 3.x may render the same exact label as a Markdown bullet:
    #
    #   * Final recommended bucket: **Borderline / manual review recommended**::
    #
    # Accept one optional Markdown ``*`` bullet plus following horizontal
    # whitespace, while still requiring the exact label, Markdown bold bucket,
    # a single-line value, and only the historical optional trailing ``::``.
    # No prompt, bucket mapping, or severity rule is changed.
    bucket_match = re.search(
        r"(?m)Final recommended bucket:\s*\*\*([^\r\n*]+?)\*\*\s*(?:::)?\s*$",
        text,
    )
    if not bucket_match:
        raise ValueError("missing Final recommended bucket")

    final_bucket = bucket_match.group(1).strip()

    #
    # Map ActionableScore semantics to the Aegis binary
    # IMPORTANT / MODERATE decision.
    #
    # For this POC we intentionally follow the semantic conclusion,
    # not CVSS.
    #
    def _map_actionable_bucket_to_impact(
        bucket_text: str,
    ) -> Literal["MODERATE", "IMPORTANT"]:
        bucket = bucket_text.strip()

        # Unambiguously Important-side buckets.
        #
        # Use startswith intentionally because Gemini may emit variants such as:
        #
        #   Strong Important candidate
        #
        # or:
        #
        #   Strong Important candidate / Actionable Moderate at minimum
        #
        if bucket.startswith("High-end Important"):
            return "IMPORTANT"

        if bucket.startswith("Strong Important candidate"):
            return "IMPORTANT"

        # Hybrid / borderline buckets remain MODERATE as the semantic
        # classification. Manual-review requirements are handled separately
        # and must not automatically mean IMPORTANT.
        return "MODERATE"

    recommended_impact = _map_actionable_bucket_to_impact(final_bucket)

    parsed = KernelSecondOpinionModel(
        actionable_score=score,
        actionable_score_lower=lower,
        primitive_class=cast(
            Literal["NONE", "CLASS_A", "CLASS_B", "CLASS_C"], primitive_class
        ),
        real_uaf=cast(Literal["YES", "NO"], real_uaf),
        host_admin_required=cast(Literal["YES", "NO", "UNKNOWN"], host_admin),
        namespace_scoped_privilege=cast(
            Literal["YES", "NO", "UNKNOWN"], namespace_priv
        ),
        important_candidate=cast(Literal["YES", "NO"], important_candidate),
        manual_review=cast(Literal["NO", "RECOMMENDED", "REQUIRED"], manual_review),
        auto_downgrade_allowed=cast(Literal["YES", "NO"], auto_downgrade),
        cvss_selected_score=cvss_selected_score,
        cvss_selected_vector=cvss_selected_vector,
        final_bucket=final_bucket,
        recommended_impact=recommended_impact,
        raw_response=text,
    )

    logger.info(
        "%s: ACTIONABLE_SCORE parsed score=%s lower=%s "
        "primitive=%s important_candidate=%s manual_review=%s "
        "auto_downgrade=%s selected_cvss=%s selected_vector=%s "
        "bucket=%s mapped_impact=%s",
        call_str,
        parsed.actionable_score,
        parsed.actionable_score_lower,
        parsed.primitive_class,
        parsed.important_candidate,
        parsed.manual_review,
        parsed.auto_downgrade_allowed,
        parsed.cvss_selected_score,
        parsed.cvss_selected_vector,
        parsed.final_bucket,
        parsed.recommended_impact,
    )

    return parsed


# end of "Inserted by A.Larkin, dirty hack"


def _build_cve_input(cve_id: CVEID, static_context: Any = None) -> CVEFeatureInput:
    if isinstance(static_context, dict):
        desc = (
            static_context.get("comment_zero")
            or static_context.get("cve_description")
            or static_context.get("description")
        )
        return CVEFeatureInput(
            cve_id=cve_id,
            title=static_context.get("title"),
            description=desc,
            cwe_id=static_context.get("cwe_id"),
            impact=static_context.get("impact"),
            statement=static_context.get("statement"),
            mitigation=static_context.get("mitigation"),
            comment_zero=static_context.get("comment_zero"),
            comments=static_context.get("comments"),
            components=static_context.get("components"),
            references=static_context.get("references"),
            affects=static_context.get("affects"),
            cvss_scores=static_context.get("cvss_scores"),
        )
    return CVEFeatureInput(cve_id=cve_id)


# Classifier feature -> OSIDB label name.
# Multiple features can map to the same label (deduped).
_FLAG_TO_LABEL: dict[str, str] = {
    "kernel_panic": "kpanic",
    "kernel_panic_plus_uaf": "kpanic",
}


class SuggestImpact(Feature):
    """Based on current CVE information and context assert an aggregated impact."""

    @staticmethod
    def post_process_cvss(output, call_str):
        # read the suggested cvss3_score
        try:
            cvss3_score = float(output.cvss3_score)
        except ValueError:
            cvss3_score = float("nan")

        # compute CVSS3 score from the suggested cvss3_vector
        try:
            cvss3_score_by_vector = cvss.CVSS3(output.cvss3_vector).scores()[0]
        except Exception:
            cvss3_score_by_vector = float("nan")

        if cvss3_score == cvss3_score_by_vector:
            # already consistent
            return

        logger.info(
            f"{call_str}: adjusting cvss3_score to match cvss3_vector: {cvss3_score} -> {cvss3_score_by_vector}"
        )
        output.cvss3_score = f"{cvss3_score_by_vector}"

    _RULES_BASE = """
                - Output format (must follow exactly):
                    - cvss3_vector: "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
                      where AV in [N,A,L,P], AC in [L,H], PR in [N,L,H], UI in [N,R], S in [U,C], C/I/A in [N,L,H].
                    - cvss3_score: numeric string matching the vector (we will verify and adjust if needed).
                    - impact: Critical/Important/Moderate/Low based on the score.
                      CRITICAL (CVSS > 9.0) is exceptionally rare in Red Hat's taxonomy (< 2% of all CVEs). It requires unauthenticated remote exploitation (AV:N/AC:L/PR:N/UI:N) with broad impact across at least two of C:H, I:H, A:H affecting user data. When uncertain between CRITICAL and IMPORTANT, choose IMPORTANT.
                - Metric selection guide:
                    - AV: N if reachable over network from off-host; A if same subnet/Bluetooth/802.11 link-limited; L if requires local account/session/CLI/local IPC; P if requires physical access.
                    - AC: H if requires uncommon configuration, precise timing/race, multiple conditions, or lengthy preparation; else L.
                    - PR: N if no prior auth; L if basic/local user privileges are enough; H if admin/root/high-privileges are required to trigger.
                    - Linux capabilities: Treat required CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_MODULE, and similar admin-class capabilities as strong evidence for PR:H when the vulnerable operation cannot be triggered without them.
                    - Kernel attack surface: Mounting filesystems (mount(2)), loading filesystem or network driver modules, configuring interfaces or traffic classes, or privileged ioctls usually implies PR:H unless the advisory clearly shows exploitation by an unprivileged user without those capabilities (e.g. unprivileged user namespaces with a specific exposed entry point).
                    - UI: R if victim must click/open/provide content; else N.
                    - S: C only when exploitation changes scope between security authorities (e.g. container/guest escape to host, crossing VM or user-namespace boundary per CVSS definition). Do not choose S:C merely because the kernel is involved or because other processes exist on the system; many local kernel bugs remain S:U.
                    - CIA: Set each based on realistic consequences: use A for availability-only DoS; use C/I when plausible user-visible confidentiality or integrity impact exists. For internal kernel object lifetime/corruption with no direct user data read/write, prefer C:N/I:N or low scores unless a credible path to disclosure or controlled modification of user data is described.
                    - Linux networking internals (tc, qdisc, net_sched, classifiers, queue discipline): flaws confined to internal queue/scheduling/state or buffer accounting for traffic shaping usually do not read or forge application payload data. Prefer C:N and I:N unless the advisory describes a concrete cross-boundary or user-data effect (e.g. leaking packet contents or socket buffers to userspace, forging another user's traffic, container-to-host data leak). Do not set C:H or I:H from generic "memory corruption" or "undefined behavior" alone; if you output C:H or I:H, the explanation must spell out that user-data impact path in one sentence.
                    - SSRF / server-side request forgery / path traversal through proxies or datasource plugins: S: Usually S:U — the attacker operates within the vulnerable application's security authority even when reaching backend services. Reserve S:C for cases where the SSRF crosses a container, VM, or sandbox boundary. CIA: Score each metric based on what the advisory concretely demonstrates, not theoretical worst-case extrapolation. "Could potentially reach internal endpoints" alone does not justify C:H, I:H, or A:H. If the advisory does not demonstrate credential disclosure, use C:N or C:L. If it describes limited state-changing actions (e.g., cache flush), use I:L rather than I:H. If disruption is recoverable or partial, use A:L rather than A:H.
                - Consider Red Hat hardening defaults (SELinux enforcing, least privilege) only to inform AC and S, not AV.
                - After calling osidb_flaw_tool, you MUST pass the flaw's reference URLs to external_references_tool to retrieve upstream CVSS vectors, security advisories, and commit details. This is critical for accurate scoring.
                - Use github mcp and web search tools for additional context if needed.
                - If cisa_kev_tool is available, check for known exploits.
                - Data quality:
                    - Set data_quality to reflect how much actionable technical detail the input (comment_zero / CVE description) provides for CVSS scoring.
                    - Reserve 0.9–1.0 only when the input spells out attack vector, privileges, user interaction, scope, and concrete CIA consequences.
                    - Use 0.6–0.8 when the input gives a general idea of the flaw but omits some metrics-relevant detail (e.g., no exploitation path, unclear privilege requirements).
                    - Use 0.3–0.5 when the input is vague, merely names a vulnerability class, or lacks technical context.
                    - Use below 0.3 when the input is essentially empty or uninformative.
                - Confidence:
                    - Set confidence to reflect how reliable the overall suggestion is. Be conservative.
                    - Reserve 0.9–1.0 only when input data is unambiguous and you are near-certain about the vector, score, and impact.
                    - Use 0.6–0.8 when most metrics are clear but one or two require assumptions (e.g., unclear scope or privilege level).
                    - Use 0.3–0.5 when significant guesswork is involved due to sparse or ambiguous input.
                    - Use below 0.3 when the suggestion is largely speculative.
                - Mozilla/Firefox/Thunderbird CVEs with sparse input (e.g. "Undefined behavior in X component"):
                    - The comment_zero is often just one generic sentence. Use external_references_tool to fetch the Mozilla security advisory — it contains an explicit impact label per CVE.
                    - Map Mozilla's impact labels to Red Hat severity: critical → Critical, high → Important, moderate → Moderate, low → Low.
                    - When the comment_zero is vague and Mozilla's advisory provides an impact label, treat that label as the primary impact signal and construct a CVSS vector whose score falls within the matching band (Critical > 9.0, Important 7.1–9.0, Moderate 4.0–7.0, Low 0.1–3.9). This ensures the impact is not overridden by post-processing reconciliation.
                    - For these sparse-input CVEs, set data_quality to 0.3–0.5 and confidence to 0.3–0.5 to reflect the limited technical detail available.
                - Explanation must match the vector (mandatory):
                    - Do not write that exploitation requires admin capabilities, mount privileges, or privileged syscalls and output PR:L; use PR:H when those are required to trigger the flaw.
                    - If you revise the narrative and it implies stricter privileges than your draft vector, update PR in the vector before finalizing.
                - Output
                    - Provide the vector and score first, then impact, then a concise explanation with metric-by-metric rationale.
                    - Keep explanations concise.
            """

    def _check_output(self, result, deps) -> str | None:
        return check_kernel_output(result.output, deps)

    @staticmethod
    def reconcile_severity(
        output,
        call_str,
        classifier_result=None,
        second_opinion=None,
    ) -> str:
        """Bidirectional severity reconciliation.

        Dispatches to one of two paths:

        **Kernel path** (classifier_result present): threshold-based
        reconciliation ported from al-kernel.  The classifier's
        cascade-adjusted prediction is the starting severity; the LLM's
        own CVSS score drives deterministic threshold rules (H1–H11).

        **Non-kernel path** (no classifier): LLM self-consistency check.
        If the LLM's stated impact matches its CVSS band, keep it.  If
        they disagree, trust the CVSS band (quantitative > qualitative).
        In both cases, CRITICAL is capped to IMPORTANT unless the
        CVSS vector objectively supports it (AV:N/AC:L/PR:N/UI:N
        with at least two of C:H, I:H, A:H).

        The kernel path additionally applies specific guardrails
        (G2–G5) based on classifier-provided feature flags (memory
        corruption, network exposure, contained subsystems, etc.).

        Returns a trace string explaining the decision.
        """
        if classifier_result and isinstance(classifier_result, dict):
            return reconcile_kernel(
                output,
                call_str,
                classifier_result,
                second_opinion=second_opinion,
            )

        # --- Non-kernel path: LLM self-consistency ---
        SEV = SEVERITY_ORDER

        try:
            llm_cvss = float(output.cvss3_score)
        except (ValueError, TypeError):
            llm_cvss = float("nan")

        llm_cvss_band = score_to_band(llm_cvss)
        llm_impact = (output.impact or "").strip().upper()

        if not llm_cvss_band or llm_cvss_band not in SEV:
            return ""
        if llm_impact not in SEV:
            return ""

        if llm_impact == llm_cvss_band:
            trace = (
                f"path=non_kernel; llm_cvss={llm_cvss:.1f}; "
                f"band={llm_cvss_band}; stated={llm_impact}; "
                f"consistent=true; result={llm_impact}"
            )
            logger.info(
                "%s: reconciliation confirmed %s (%s)",
                call_str,
                llm_impact,
                trace,
            )
            return trace

        final = llm_cvss_band
        trace = (
            f"path=non_kernel; llm_cvss={llm_cvss:.1f}; "
            f"band={llm_cvss_band}; stated={llm_impact}; "
            f"consistent=false; result={final}"
        )
        logger.info(
            "%s: reconciled %s -> %s (%s)",
            call_str,
            output.impact,
            final,
            trace,
        )
        output.impact = final
        return trace

    _BAND_SCORE_FLOOR: dict[str, float] = {  # noqa: RUF012
        "CRITICAL": 9.1,
        "IMPORTANT": 7.1,
        "MODERATE": 4.0,
        "LOW": 0.1,
    }

    @staticmethod
    def align_score_to_impact(output, call_str) -> None:
        """Bump CVSS score to the band floor when reconciliation moved
        impact above the score's natural band.

        Only called when reconciliation actually changed the impact, so
        LLM-originated mismatches that reconciliation left alone are not
        touched here.
        """
        try:
            score = float(output.cvss3_score)
        except (ValueError, TypeError):
            return

        band = score_to_band(score)
        if band is None or band == output.impact:
            return

        sev = SEVERITY_ORDER
        impact_rank = sev.get(output.impact, 99)
        band_rank = sev.get(band, 99)

        if impact_rank < band_rank:
            floor = SuggestImpact._BAND_SCORE_FLOOR.get(output.impact)
            if floor is not None:
                logger.info(
                    "%s: bumping cvss3_score %.1f -> %.1f to align with "
                    "reconciled impact %s (was band %s)",
                    call_str,
                    score,
                    floor,
                    output.impact,
                    band,
                )
                output.cvss3_score = f"{floor}"

    @staticmethod
    def post_process(
        output,
        call_str,
        classifier_result=None,
        second_opinion=None,
    ):
        SuggestImpact.post_process_cvss(output, call_str)
        pre_reconcile_impact = output.impact
        trace = SuggestImpact.reconcile_severity(
            output,
            call_str,
            classifier_result=classifier_result,
            second_opinion=second_opinion,
        )

        override_trace = apply_kpanic_cvss_override(
            output,
            call_str,
            classifier_result,
            second_opinion=second_opinion,
        )
        if override_trace:
            trace = f"{trace}; {override_trace}"
        elif output.impact != pre_reconcile_impact:
            SuggestImpact.align_score_to_impact(output, call_str)

        return trace

    _CVSS_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

    @staticmethod
    def _diff_vector_metrics(
        old_vector: str, new_vector: str
    ) -> tuple[list[str], list[str]]:
        """Compare two CVSS 3.1 vectors and return (changed, unchanged)
        metric descriptions.

        Returns two lists:
          changed  – e.g. ["AC changed from L to H", "S changed from C to U"]
          unchanged – e.g. ["AV", "PR", "UI", "C", "I"]
        """
        old = cvss.CVSS3(old_vector).original_metrics or {}
        new = cvss.CVSS3(new_vector).original_metrics or {}
        changed: list[str] = []
        unchanged: list[str] = []
        for m in SuggestImpact._CVSS_METRICS:
            ov, nv = old.get(m), new.get(m)
            if ov != nv and ov is not None and nv is not None:
                changed.append(f"{m} changed from {ov} to {nv}")
            else:
                unchanged.append(m)
        return changed, unchanged

    async def _experimental_kernel_second_opinion(
        self,
        result,
        deps,
        classifier_result: dict | None,
        call_str: str,
        kernel_context=None,
    ):
        """TEMPORARY LOCAL EXPERIMENT.

        Run the original ActionableScore rubric using Gemini against the
        already-cached kernel patch/mbox context.

        Gemini returns the original machine-readable ActionableScore text.
        We parse that text locally and map the final semantic bucket to
        MODERATE or IMPORTANT.
        """

        if not classifier_result or not isinstance(classifier_result, dict):
            return None

        if not kernel_context:
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION no kernel context available",
                call_str,
            )
            return None

        try:
            actionable_prompt = _load_actionable_score_prompt()
        except Exception as exc:
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION cannot load prompt: %s",
                call_str,
                exc,
            )
            return None

        patch_summaries = []

        if isinstance(classifier_result, dict):
            patch_summaries = classifier_result.get("patch_summaries") or []

        if isinstance(patch_summaries, list):
            patch_context = "\n\n--- PATCH ---\n\n".join(
                str(x) for x in patch_summaries
            )
        else:
            patch_context = str(patch_summaries)

        # ------------------------------------------------------------
        # A.Larkin NN+LLM parity POC.
        #
        # BEFORE:
        #   ActionableScore was intentionally isolated from primary Aegis
        #   impact/CVSS.
        #
        # AFTER:
        #   Feed primary-LLM hints into ActionableScore, but still omit XGBoost
        #   prediction/flags/confidence.
        #
        # PERL SOURCE:
        #   request_llm_calculate_awareness(
        #     $htmltext . " and as input hints from previous LLM call for "
        #     "analyses of this patch is " . $rs
        #   );
        #
        # WHY:
        #   In NN+LLM ActionableScore is explicitly the second LLM pass and sees
        #   the first LLM result. This restores the same information flow.
        # ------------------------------------------------------------
        # A.Larkin remove CVSS from ActionableScore primary_hints.
        #
        # Keep the primary LLM's structured/manual technical hints, but do not
        # pass its CVSS vector or numeric score into the ActionableScore model.
        #
        # WHY:
        # Primary Aegis CVSS can anchor the second LLM toward an already-selected
        # severity/CIA conclusion. ActionableScore already receives kernel context
        # and raw fix patch data, so it should derive its own score independently.
        #
        # Intentionally still passed:
        #   - manual-review hint
        #   - NULL/CWE-related hint
        #   - btrfs-context hint
        #   - primary technical explanation
        #
        # Intentionally no longer passed:
        #   - primary CVSS vector
        #   - primary CVSS score
        primary_hints = (
            "PRIMARY LLM HINTS FROM THE PREVIOUS ANALYSIS:\n"
            "=============================================\n"
            f"Manual review: {getattr(result.output, 'kernel_manual_review', 'UNKNOWN')}\n"
            f"NULL/CWE-476/CWE-833/CWE-401 related: "
            f"{getattr(result.output, 'kernel_nullptr_related', False)}\n"
            f"btrfs context: {getattr(result.output, 'kernel_btrfs_context', False)}\n"
            f"Technical explanation:\n{result.output.explanation}\n"
        )

        prompt = (
            actionable_prompt
            + "\n\n"
            + kernel_context
            + "\n\n"
            + "RAW FIX PATCH CONTEXT:\n"
            + "======================\n"
            + patch_context
            + "\n\n"
            + primary_hints
        )

        # Still deliberately NOT supplied here:
        #   current XGBoost raw/adjusted prediction
        #   classifier active flags
        #   classifier confidence

        logger.info(
            "%s: ACTIONABLE_SCORE_SECOND_OPINION "
            "prompt_chars=%d kernel_context_chars=%d",
            call_str,
            len(prompt),
            len(kernel_context),
        )

        # ------------------------------------------------------------
        # TEMP DEBUG / POC:
        # Save the EXACT text that will be passed to Gemini below.
        #
        # Example:
        #   /tmp/aegis_actionable_score_input_CVE-2026-53016.txt
        #
        # This is deliberately immediately before self._run(), so the
        # dump contains exactly:
        #
        #   actionable_score_prompt.txt + cached kernel_context
        #
        # and nothing from the current Aegis severity/CVSS/XGBoost result.
        #
        # Best-effort only: failure to write /tmp must never break Aegis.
        # ------------------------------------------------------------
        dump_id_match = re.search(r"CVE-\d{4}-\d+", call_str)
        if dump_id_match:
            dump_id = dump_id_match.group(0)
        else:
            dump_id = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "_",
                call_str,
            ).strip("_")

        prompt_dump_path = Path(f"/tmp/aegis_actionable_score_input_{dump_id}.txt")

        try:
            prompt_dump_path.write_text(prompt, encoding="utf-8")

            logger.info(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input dumped to %s "
                "(chars=%d bytes=%d)",
                call_str,
                prompt_dump_path,
                len(prompt),
                len(prompt.encode("utf-8")),
            )

            # Normally this will not appear unless DEBUG logging is enabled.
            # It is intentionally DEBUG rather than INFO because the prompt
            # is around 150k characters and would otherwise flood every log.
            logger.debug(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input BEGIN\n%s\n"
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input END",
                call_str,
                prompt,
                call_str,
            )

        except Exception as exc:
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION could not dump exact "
                "input to %s: %s",
                call_str,
                prompt_dump_path,
                exc,
            )

        try:
            #
            # Raw text output is intentional.
            #
            # The original ActionableScore prompt itself defines the output
            # contract.  This tests whether Gemini follows the same contract
            # as the OpenAI model.
            #
            second_result = await self._run(
                f"{call_str}:ActionableScoreSecondOpinion",
                prompt,
                deps=deps,
                output_type=str,
            )

            raw_text = second_result.output

            if not isinstance(raw_text, str):
                raw_text = str(raw_text)

            logger.info(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION raw_response:\n%s",
                call_str,
                raw_text,
            )

            opinion = _parse_actionable_score_response(
                raw_text,
                call_str,
            )

        except Exception as exc:
            #
            # Experimental only. Never break normal Aegis execution.
            #
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION failed: %s",
                call_str,
                exc,
            )
            return None

        return opinion

    async def _experimental_kernel_kpanic_review(
        self,
        result,
        deps,
        classifier_result: dict | None,
        second_opinion: KernelSecondOpinionModel | None,
        call_str: str,
        kernel_context: str | None,
    ) -> KernelKpanicReviewModel | None:
        """Run the NN+LLM KPANIC false-positive filter after the deterministic H/AS cascade.

        Ordering mirrors the supplied Perl daemon:
            primary triage
            -> ActionableScore
            -> deterministic H/AS cascade
            -> request_llm_kpanic()

        The later request_llm_afterpushedtohigh() stage is intentionally not
        implemented here.
        """
        # NEW56: run this specialized evidence review for every kernel CVE
        # that reached ActionableScore, even when no operational KPANIC marker
        # currently exists.  Besides panic/Important precision, it now provides
        # an independent positive safe-auto-close vote used by deferred AS7.

        if second_opinion is None:
            logger.warning(
                "%s: KPANIC_REVIEW skipped because ActionableScore result "
                "is unavailable",
                call_str,
            )
            return None

        if not kernel_context:
            logger.warning(
                "%s: KPANIC_REVIEW skipped because kernel context is unavailable",
                call_str,
            )
            return None

        try:
            kpanic_prompt = _load_kpanic_prompt()
        except Exception as exc:
            logger.warning(
                "%s: KPANIC_REVIEW cannot load kpanic_prompt.txt: %s",
                call_str,
                exc,
            )
            return None

        patch_summaries = []
        if isinstance(classifier_result, dict):
            patch_summaries = classifier_result.get("patch_summaries") or []

        if isinstance(patch_summaries, list):
            patch_context = "\n\n--- PATCH ---\n\n".join(
                str(x) for x in patch_summaries
            )
        else:
            patch_context = str(patch_summaries)

        # Equivalent of old NN+LLM:
        #
        #   $htmltext
        #   . PREVIOUS ACTIONABLESCORE ANALYSIS ($longtextforAS)
        #   . PREVIOUS TRIAGE / CVSS DESCRIPTION ($rs)
        #   . PREVIOUS ACTIONABLESCORE CONSISTENCY RULE
        #
        # The raw ActionableScore response is passed intact so this stage sees
        # the conservative/paranoid reasoning, selected CVSS, primitive class,
        # and all technical signal breakdown exactly as Gemini emitted it.
        primary_impact = (
            getattr(result.output, "_original_llm_impact", None) or result.output.impact
        )
        primary_score = (
            getattr(result.output, "_original_llm_score", None)
            or result.output.cvss3_score
        )
        primary_vector = (
            getattr(result.output, "_original_llm_vector", None)
            or result.output.cvss3_vector
        )

        primary_triage = (
            f"Primary impact: {primary_impact}\n"
            f"Primary CVSS score: {primary_score}\n"
            f"Primary CVSS vector: {primary_vector}\n"
            f"Manual review: "
            f"{getattr(result.output, 'kernel_manual_review', 'UNKNOWN')}\n"
            f"NULL/CWE-476/CWE-833/CWE-401 related: "
            f"{getattr(result.output, 'kernel_nullptr_related', False)}\n"
            f"btrfs context: "
            f"{getattr(result.output, 'kernel_btrfs_context', False)}\n"
            "Technical explanation:\n"
            f"{result.output.explanation}\n"
        )

        consistency_rule = (
            "IMPORTANT: Apply the PREVIOUS ACTIONABLESCORE CONSISTENCY RULE. "
            "Do not preserve HIGH merely because the previous text says Important. "
            "Do not use any previous numeric ActionableScore threshold as a "
            "prerequisite for preserving HIGH or as a reason to allow downgrade. "
            "Consider the underlying technical findings from both conservative "
            "and paranoid ActionableScore analyses, but independently determine "
            "whether the supplied evidence establishes a strong non-crash "
            "security primitive. A previous low conservative score must not "
            "outweigh stronger technical evidence identified at this step, "
            "including attacker-influenced kernel memory/object corruption, "
            "validation-to-use semantic reinterpretation, ownership/lifetime "
            "violations, protected-data boundary violations, or other serious "
            "kernel exploitation primitives.\n\n"
            "NEW53 OPERATIONAL KPANIC DECISION: In the JSON object also emit "
            "remove_operational_kpanic as a JSON boolean. This is a SEPARATE "
            "decision from kernel_panic_supported and from "
            "allow_high_to_moderate7_downgrade. Set "
            "remove_operational_kpanic=true ONLY when the supplied evidence "
            "affirmatively establishes that regular MODERATE is sufficient and "
            "the extended KPANIC/MODERATE7 manual-review state is no longer "
            "warranted. kernel_panic_supported=false alone is NOT sufficient. "
            "Keep it false when a documented kernel race, lifetime/list/object "
            "corruption, credible crash/fatal-failure consequence, contradictory "
            "evidence, or other unresolved kernel-security uncertainty still "
            "justifies extended review. A trigger condition explicitly stated by "
            "the upstream patch is part of the vulnerability mechanism, not an "
            "additional speculative assumption merely because it is a race. "
            "For backward compatibility, omission is parsed as false.\n\n"
            "NEW56 SAFE AUTO-CLOSE DECISION: Regardless of whether an operational "
            "KPANIC marker is currently present, also emit these THREE JSON fields: "
            "low_auto_close_supported (boolean), low_auto_close_confidence (0.0..1.0), "
            "and low_auto_close_reason (string). Set low_auto_close_supported=true "
            "ONLY when the patch/kernel evidence positively establishes a bounded "
            "LOW-impact bug that is safe to auto-close without analyst review. "
            "Absence of evidence for Important is NOT evidence for LOW. Return false "
            "for unresolved races/lifetime/list/object corruption, UAF/OOB/write or "
            "ownership/authorization primitives, contradictory evidence, plausible "
            "confidentiality/integrity or privilege-boundary effects, or when the "
            "trigger/reachability/impact remains materially uncertain. A mere low "
            "ActionableScore, low selected CVSS, ImportantCandidate=NO, or "
            "AutoDowngradeAllowed=YES is NOT sufficient because those fields came "
            "from the same earlier LLM turn. true should mean this independent "
            "specialized reread affirmatively agrees that LOW auto-close is safe. "
            "Use confidence >=0.85 only when that conclusion is well supported.\n\n"
            "NEW57 INDEPENDENT MANUAL-REVIEW ROUTING: Also emit "
            "manual_review_still_required (boolean), manual_review_confidence "
            "(0.0..1.0), and manual_review_reason (string). Re-read the supplied "
            "technical evidence independently of the previous ActionableScore "
            "ManualReview field. Set manual_review_still_required=true when a "
            "concrete security-significant mechanism still requires analyst "
            "judgment even if kernel_panic_supported=false and even if regular "
            "MODERATE severity is otherwise appropriate. Examples include a "
            "concrete cross-security-boundary authorization/ownership violation, "
            "protected-resource modification, unresolved memory/lifetime/corruption "
            "mechanics, supported crash/fatal behavior, or another specific "
            "security consequence whose safe disposition requires human review. "
            "Do NOT set it true merely because the previous ActionableScore said "
            "RECOMMENDED/REQUIRED, because a CVSS score is Moderate, or because an "
            "operational KPANIC marker already exists. This verdict controls review "
            "routing only: it MUST NOT promote severity or preserve IMPORTANT by "
            "itself. If manual_review_still_required=true with confidence >=0.85, "
            "the operational MODERATE7 review marker must not be removed."
        )

        prompt = (
            kpanic_prompt
            + "\n\n=== KERNEL / PATCH EVIDENCE ===\n"
            + kernel_context
            + "\n\n=== RAW FIX PATCH CONTEXT ===\n"
            + patch_context
            + "\n\n=== PREVIOUS ACTIONABLESCORE ANALYSIS ===\n"
            + second_opinion.raw_response
            + "\n\n=== PREVIOUS TRIAGE / CVSS DESCRIPTION ===\n"
            + primary_triage
            + "\n\n=== CURRENT POST-CASCADE OPERATIONAL STATE ===\n"
            + f"Impact after H1-H15/AS1-AS7: {result.output.impact}\n"
            + "Operational KPANIC marker: "
            + (
                "YES"
                if getattr(result.output, "_kernel_kpanic_marked", False)
                else "NO"
            )
            + "\n"
            + "lowered: "
            + ("YES" if getattr(result.output, "_kernel_lowered", False) else "NO")
            + "\n"
            + f"dec_cnt: {getattr(result.output, '_kernel_decrease_count', 0)}\n"
            + "pushed_to_high: "
            + (
                "YES"
                if getattr(result.output, "_kernel_pushed_to_high", False)
                else "NO"
            )
            + "\n\n"
            + consistency_rule
        )

        logger.info(
            "%s: KPANIC_REVIEW prompt_chars=%d kernel_context_chars=%d",
            call_str,
            len(prompt),
            len(kernel_context),
        )

        dump_id_match = re.search(r"CVE-\d{4}-\d+", call_str)
        dump_id = (
            dump_id_match.group(0)
            if dump_id_match
            else re.sub(r"[^A-Za-z0-9_.-]+", "_", call_str).strip("_")
        )
        prompt_dump_path = Path(f"/tmp/aegis_kpanic_input_{dump_id}.txt")

        try:
            prompt_dump_path.write_text(prompt, encoding="utf-8")
            logger.info(
                "%s: KPANIC_REVIEW exact input dumped to %s (chars=%d bytes=%d)",
                call_str,
                prompt_dump_path,
                len(prompt),
                len(prompt.encode("utf-8")),
            )
        except Exception as exc:
            logger.warning(
                "%s: KPANIC_REVIEW could not dump exact input to %s: %s",
                call_str,
                prompt_dump_path,
                exc,
            )

        try:
            review_result = await self._run(
                f"{call_str}:KernelPanicFalsePositiveReview",
                prompt,
                deps=deps,
                output_type=str,
            )
            raw_text = review_result.output
            if not isinstance(raw_text, str):
                raw_text = str(raw_text)

            logger.info(
                "%s: KPANIC_REVIEW raw_response:\n%s",
                call_str,
                raw_text,
            )
            return _parse_kpanic_review_response(raw_text, call_str)

        except Exception as exc:
            # Parity experiment must never break the normal Aegis result.
            logger.warning(
                "%s: KPANIC_REVIEW failed; keeping pre-review result: %s",
                call_str,
                exc,
            )
            return None

    async def _experimental_kernel_afterpushed_review(
        self,
        result,
        deps,
        classifier_result: dict | None,
        second_opinion: KernelSecondOpinionModel | None,
        call_str: str,
        kernel_context: str | None,
    ) -> KernelAfterPushedHighReviewModel | None:
        """Run the old request_llm_afterpushedtohigh()-equivalent review.

        The call is gated exactly at the old outer Perl condition:
            pushed_to_high && current severity == HIGH/IMPORTANT

        The inner Perl downgrade gates are enforced later in kernel.py.
        """
        if not getattr(result.output, "_kernel_pushed_to_high", False):
            logger.info(
                "%s: AFTERPUSHED_REVIEW skipped because pushed_to_high=NO",
                call_str,
            )
            return None

        if result.output.impact != "IMPORTANT":
            logger.info(
                "%s: AFTERPUSHED_REVIEW skipped because current impact=%s",
                call_str,
                result.output.impact,
            )
            return None

        if second_opinion is None:
            logger.warning(
                "%s: AFTERPUSHED_REVIEW skipped because ActionableScore result is unavailable",
                call_str,
            )
            return None

        if not kernel_context:
            logger.warning(
                "%s: AFTERPUSHED_REVIEW skipped because kernel context is unavailable",
                call_str,
            )
            return None

        try:
            review_prompt = _load_afterpushed_prompt()
        except Exception as exc:
            logger.warning(
                "%s: AFTERPUSHED_REVIEW cannot load afterpushedtohigh_prompt.txt: %s",
                call_str,
                exc,
            )
            return None

        patch_summaries = []
        if isinstance(classifier_result, dict):
            patch_summaries = classifier_result.get("patch_summaries") or []
        if isinstance(patch_summaries, list):
            patch_context = "\n\n--- PATCH ---\n\n".join(
                str(x) for x in patch_summaries
            )
        else:
            patch_context = str(patch_summaries)

        primary_impact = (
            getattr(result.output, "_original_llm_impact", None) or result.output.impact
        )
        primary_score = (
            getattr(result.output, "_original_llm_score", None)
            or result.output.cvss3_score
        )
        primary_vector = (
            getattr(result.output, "_original_llm_vector", None)
            or result.output.cvss3_vector
        )

        primary_triage = (
            f"Primary impact: {primary_impact}\n"
            f"Primary CVSS score: {primary_score}\n"
            f"Primary CVSS vector: {primary_vector}\n"
            f"Manual review: {getattr(result.output, 'kernel_manual_review', 'UNKNOWN')}\n"
            f"NULL/CWE-476/CWE-833/CWE-401 related: "
            f"{getattr(result.output, 'kernel_nullptr_related', False)}\n"
            f"btrfs context: {getattr(result.output, 'kernel_btrfs_context', False)}\n"
            "Technical explanation:\n"
            f"{result.output.explanation}\n"
        )

        consistency_rule = (
            "IMPORTANT: Apply the PREVIOUS ACTIONABLESCORE CONSISTENCY RULE. "
            "Do not preserve HIGH merely because the previous text says Important. "
            "Preserve HIGH when the previous conservative ActionableScore is >= 7 "
            "and that score is independently supported by a concrete non-crash "
            "shared-page/pagecache/COW/ownership security primitive rather than "
            "speculative kernel panic or generic worst-case reasoning."
        )

        prompt = (
            review_prompt
            + "\n\n=== KERNEL / PATCH EVIDENCE ===\n"
            + kernel_context
            + "\n\n=== RAW FIX PATCH CONTEXT ===\n"
            + patch_context
            + "\n\n=== PREVIOUS ACTIONABLESCORE ANALYSIS ===\n"
            + second_opinion.raw_response
            + "\n\n=== PREVIOUS TRIAGE / CVSS DESCRIPTION ===\n"
            + primary_triage
            + "\n\n=== CURRENT POST-KPANIC-REVIEW OPERATIONAL STATE ===\n"
            + f"Impact: {result.output.impact}\n"
            + "Operational KPANIC marker: "
            + (
                "YES"
                if getattr(result.output, "_kernel_kpanic_marked", False)
                else "NO"
            )
            + "\n"
            + "lowered: "
            + ("YES" if getattr(result.output, "_kernel_lowered", False) else "NO")
            + "\n"
            + f"dec_cnt: {getattr(result.output, '_kernel_decrease_count', 0)}\n"
            + "pushed_to_high: YES\n\n"
            + consistency_rule
        )

        logger.info(
            "%s: AFTERPUSHED_REVIEW prompt_chars=%d kernel_context_chars=%d",
            call_str,
            len(prompt),
            len(kernel_context),
        )

        dump_id_match = re.search(r"CVE-\d{4}-\d+", call_str)
        dump_id = (
            dump_id_match.group(0)
            if dump_id_match
            else re.sub(r"[^A-Za-z0-9_.-]+", "_", call_str).strip("_")
        )
        dump_path = Path(f"/tmp/aegis_afterpushed_input_{dump_id}.txt")
        try:
            dump_path.write_text(prompt, encoding="utf-8")
            logger.info(
                "%s: AFTERPUSHED_REVIEW exact input dumped to %s (chars=%d bytes=%d)",
                call_str,
                dump_path,
                len(prompt),
                len(prompt.encode("utf-8")),
            )
        except Exception as exc:
            logger.warning(
                "%s: AFTERPUSHED_REVIEW could not dump exact input to %s: %s",
                call_str,
                dump_path,
                exc,
            )

        try:
            review_result = await self._run(
                f"{call_str}:AfterPushedToHighReview",
                prompt,
                deps=deps,
                output_type=str,
            )
            raw_text = review_result.output
            if not isinstance(raw_text, str):
                raw_text = str(raw_text)
            logger.info(
                "%s: AFTERPUSHED_REVIEW raw_response:\n%s",
                call_str,
                raw_text,
            )
            return _parse_afterpushed_review_response(raw_text, call_str)
        except Exception as exc:
            logger.warning(
                "%s: AFTERPUSHED_REVIEW failed; keeping pre-review result: %s",
                call_str,
                exc,
            )
            return None

        # Older ver before trying ActionableScore (that was much simplified:
        #    async def _experimental_kernel_second_opinion(
        #        self,
        #        result,
        #        deps,
        #        classifier_result: dict | None,
        #        call_str: str,
        #        kernel_context=None,
        #    ):
        #        """TEMPORARY LOCAL EXPERIMENT.
        #
        #        Run an independent kernel-specific LLM pass for IMPORTANT or
        #        kernel-panic cases.  It can only distinguish IMPORTANT from
        #        MODERATE; it can never produce LOW.
        #        """
        #
        #        if not classifier_result or not isinstance(classifier_result, dict):
        #            return None
        #
        #        output = result.output
        #
        #        active_features = set(classifier_result.get("active_features", []))
        #        has_kpanic = (
        #            "kernel_panic" in active_features
        #            or "kernel_panic_plus_uaf" in active_features
        #        )
        #
        #        # First experiment: only examine the interesting boundary.
        #        if output.impact != "IMPORTANT" and not has_kpanic:
        #            return None
        #
        #
        #        prompt = f"""
        # You are an independent second-opinion Linux kernel security analyst.
        #
        # Target vulnerability: {call_str}
        # CVE:
        # (so take CVE ID from this target vulnerability str)
        #
        # The following Linux kernel CVE context was already retrieved earlier by
        # kernel_cve_tool during the primary Aegis analysis.
        #
        # Do NOT call kernel_cve_tool again.
        #
        # Treat the kernel context below as the primary technical evidence for this
        # validation. Analyze the actual bug mechanism, affected object or buffer,
        # object lifetime, patch semantics, attacker prerequisites, and the concrete
        # security primitive created by successful triggering of the vulnerability.
        #
        # The kernel context may contain descriptive or severity-assessment prose
        # written by CVE authors or vendors.
        #
        # Do NOT treat statements such as:
        #
        # - "may allow memory corruption";
        # - "may allow privilege escalation";
        # - "integrity impact is high";
        # - "confidentiality impact is possible";
        # - "could allow code execution";
        #
        # as proof of a concrete primitive.
        #
        # Those statements are conclusions to be independently validated.
        #
        # Base your decision on the actual data flow, memory operation, object
        # lifetime, bounds relationship, attacker-controlled inputs, and patch
        # semantics.
        #
        # Do not simply agree with the existing Aegis classification.
        #
        # Do NOT infer severity merely from:
        # - CWE names;
        # - CVSS values;
        # - the current Aegis impact;
        # - classifier flags;
        # - generic labels such as UAF, OOB, double-free, race, networking,
        #  memory corruption, or kernel panic.
        #
        # IMPORTANT:
        # The current Aegis CVSS vector and C/I/A values may themselves be wrong.
        # Do NOT use existing C:H, I:H, or A:H values as evidence that confidentiality,
        # integrity, code execution, arbitrary read/write, or another security primitive
        # actually exists.
        #
        # KERNEL CONTEXT
        # ==============
        # {kernel_context or "Kernel context was not available."}
        # ==============
        #
        # Current Aegis result:
        # Impact: {output.impact}
        # CVSS vector: {output.cvss3_vector}
        # CVSS score: {output.cvss3_score}
        #
        # Kernel classifier active features:
        # {sorted(active_features)}
        #
        # Your task is ONLY to distinguish IMPORTANT from MODERATE.
        #
        # First determine the concrete primitive supported by the vulnerability and
        # patch semantics.
        #
        # The question is NOT merely whether some non-crash effect is theoretically
        # possible.
        #
        # The question is whether the evidence supports a sufficiently concrete and
        # powerful security primitive to justify IMPORTANT rather than MODERATE.
        #
        # Recommend IMPORTANT when the technical evidence directly supports a useful,
        # security-significant primitive such as:
        #
        # - attacker-controlled or meaningfully controllable write to a useful target;
        # - useful post-free access or reuse where the attacker retains meaningful
        #  control after the object is freed;
        # - freed backing memory or pages remaining accessible or mapped to the attacker;
        # - attacker-controlled OOB access with useful target and/or value control;
        # - concrete information disclosure;
        # - concrete authorization or privilege bypass with meaningful security impact;
        # - cross-security-boundary escape;
        # - direct corruption of protected data or security-sensitive state;
        # - another realistic confidentiality or integrity primitive supported by the
        #  actual code and patch.
        #
        # Recommend MODERATE when the realistic supported consequence is primarily:
        #
        # - crash;
        # - kernel panic;
        # - denial of service;
        # - bounded or constrained corruption without a demonstrated useful target;
        # - stale-pointer or UAF behavior without evidence of useful post-free control;
        # - double-free without evidence of a useful reuse/dereference primitive;
        # - OOB write where the attacker controls bytes but not a useful destination;
        # - authorization/configuration bypass whose scope and attacker advantage are
        #  narrow or limited;
        # - a hypothetical exploit chain requiring several unsupported assumptions.
        #
        # IMPORTANT DISTINCTION:
        # Do not confuse exploit reliability with primitive strength.
        #
        # A narrow race window, difficult heap grooming, or AC:H does NOT by itself
        # justify MODERATE if successful exploitation clearly provides a strong,
        # useful confidentiality or integrity primitive.
        #
        # However, the reverse is also important:
        #
        # Do not promote to IMPORTANT merely because exploitation might theoretically
        # be possible.
        #
        # For example, reasoning like:
        #
        # double-free
        # -> memory might be reallocated
        # -> this might become a UAF
        # -> metadata might be corrupted
        # -> arbitrary write might therefore be possible
        #
        # is speculative and is NOT sufficient evidence for IMPORTANT unless the actual
        # code, object lifetime, or patch supports those intermediate steps.
        #
        # Likewise:
        #
        # - attacker-controlled bytes are NOT automatically an attacker-controlled
        #  arbitrary write;
        # - a stale pointer is NOT automatically a useful UAF primitive;
        # - a UAF is NOT automatically arbitrary read/write;
        # - an OOB write is NOT automatically code execution;
        # - network reachability is NOT automatically IMPORTANT;
        # - a privilege or authorization mismatch is NOT automatically Important-grade
        #  unless the resulting boundary bypass is sufficiently meaningful.
        #
        # For memory corruption, explicitly distinguish these questions:
        #
        # 1. What exact object, page, field, buffer, or allocation becomes stale,
        #   freed, overwritten, or out of bounds?
        #
        # 2. What exactly can the attacker control before the violation?
        #
        # 3. What exactly can the attacker control after the violation?
        #
        # 4. Does the attacker control the written value?
        #   If yes, is that control full, partial, fixed-width, constrained, or fixed?
        #
        # 5. Does the attacker control the destination or victim object?
        #   If yes, is it arbitrary, meaningfully selectable, constrained, or fixed?
        #
        # 6. For a UAF or double-free, is there evidence that freed memory can be
        #   reallocated and then accessed or modified through the stale reference?
        #
        # 7. For a stale pointer, what operation is actually performed through it after
        #   the lifetime transition?
        #
        # 8. For an OOB write, what lies beyond the boundary, and is corruption of that
        #   destination useful rather than merely crash-inducing?
        #
        # 9. For authorization or namespace bugs, what privilege does the attacker
        #   already possess, what additional authority is gained, and how broad is the
        #   affected security boundary?
        #
        # 10. Is the claimed confidentiality or integrity primitive directly supported
        #    by the kernel context and patch, merely plausible, or speculative?
        #
        # Set useful_non_crash_primitive=true only when there is concrete technical
        # evidence for a useful confidentiality, integrity, authorization, mapping,
        # lifetime, read, or write primitive beyond simple crash/DoS.
        #
        # Do NOT set useful_non_crash_primitive=true merely because:
        # - the bug is a UAF;
        # - the bug is an OOB write;
        # - the bug is a double-free;
        # - memory corruption exists;
        # - the current CVSS says C:H or I:H;
        # - a theoretical exploit chain can be imagined.
        #
        # Set panic_dominant=true when the supported practical effect is primarily
        # crash, kernel panic, or denial of service and no sufficiently concrete useful
        # non-crash primitive is established.
        #
        # When deciding between IMPORTANT and MODERATE, give more weight to directly
        # demonstrated primitive strength than to generic vulnerability class names.
        #
        # A useful primitive should be supported by the actual technical context,
        # not merely inferred from the vulnerability category.
        #
        # If the evidence supports only a possible or speculative non-crash primitive,
        # prefer MODERATE.
        #
        # If the evidence directly supports a strong primitive but exploitation is
        # difficult or unreliable, IMPORTANT may still be appropriate.
        #
        #
        # For oversized memcpy/memmove operations, distinguish carefully between:
        #
        # - attacker control over the length;
        # - attacker control over the initial source bytes;
        # - attacker control over all bytes copied;
        # - attacker control over the destination;
        # - attacker control over the objects corrupted beyond the destination.
        #
        # A very large attacker-triggered copy is NOT automatically a large
        # attacker-controlled write.
        #
        # If the copy runs beyond both the valid source and destination buffers,
        # do not describe the resulting bytes or corrupted targets as
        # attacker-controlled unless the code demonstrates that control.
        #
        #
        # Return a concise technical rationale that states:
        #
        # - the concrete primitive;
        # - what the attacker controls;
        # - what the attacker does not control;
        # - whether the primitive is directly established or speculative;
        # - why that evidence is sufficient for IMPORTANT or insufficient and therefore
        #  MODERATE.
        # """
        #
        #        try:
        #            second_result = await self._run(
        #                f"{call_str}:KernelSecondOpinion",
        #                prompt,
        #                deps=deps,
        #                output_type=KernelSecondOpinionModel,
        #            )
        #        except Exception as e:
        #            # This is experimental.  Never break normal Aegis processing
        #            # if the second opinion fails.
        #            logger.warning(
        #                "%s: SECOND_OPINION failed: %s",
        #                call_str,
        #                e,
        #            )
        #            return None
        #
        #        opinion = second_result.output
        #
        #        logger.info(
        #            "%s: SECOND_OPINION recommended=%s "
        #            "useful_non_crash=%s panic_dominant=%s "
        #            "confidence=%.2f primitive=%s rationale=%s",
        #            call_str,
        #            opinion.recommended_impact,
        #            opinion.useful_non_crash_primitive,
        #            opinion.panic_dominant,
        #            opinion.confidence,
        #            opinion.primitive,
        #            opinion.rationale,
        #        )
        #
        #        return opinion

        prompt_dump_path = Path(
            "/tmp/aegis_actionable_score_input_"
            + re.sub(r"[^A-Za-z0-9_.-]+", "_", call_str)
            + ".txt"
        )
        try:
            prompt_dump_path.write_text(prompt, encoding="utf-8")

            logger.info(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input dumped to %s "
                "(chars=%d bytes=%d)",
                call_str,
                prompt_dump_path,
                len(prompt),
                len(prompt.encode("utf-8")),
            )

            # Normally this will not appear unless DEBUG logging is enabled.
            # It is intentionally DEBUG rather than INFO because the prompt
            # is around 150k characters and would otherwise flood every log.
            logger.debug(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input BEGIN\n%s\n"
                "%s: ACTIONABLE_SCORE_SECOND_OPINION exact input END",
                call_str,
                prompt,
                call_str,
            )

        except Exception as exc:
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION could not dump exact "
                "input to %s: %s",
                call_str,
                prompt_dump_path,
                exc,
            )

        try:
            #
            # Raw text output is intentional.
            #
            # The original ActionableScore prompt itself defines the output
            # contract.  This tests whether Gemini follows the same contract
            # as the OpenAI model.
            #
            second_result = await self._run(
                f"{call_str}:ActionableScoreSecondOpinion",
                prompt,
                deps=deps,
                output_type=str,
            )

            raw_text = second_result.output

            if not isinstance(raw_text, str):
                raw_text = str(raw_text)

            logger.info(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION raw_response:\n%s",
                call_str,
                raw_text,
            )

            opinion = _parse_actionable_score_response(
                raw_text,
                call_str,
            )

        except Exception as exc:
            #
            # Experimental only. Never break normal Aegis execution.
            #
            logger.warning(
                "%s: ACTIONABLE_SCORE_SECOND_OPINION failed: %s",
                call_str,
                exc,
            )
            return None

        return opinion

    async def _revise_explanation(
        self,
        result,
        original_score,
        original_impact,
        original_vector,
        trace,
        call_str,
        *,
        deps=None,
        cve_context: dict | None = None,
    ):
        """Ask the LLM to revise its explanation after post-processing
        changed the score, impact, or CVSS vector.  Best-effort: failures
        are logged and the original explanation is kept.

        Returns True if the revision succeeded, False otherwise."""
        from aegis_ai.features import llm_prompt_timeout, llm_sem

        changes: list[str] = []
        if result.output.impact != original_impact:
            changes.append(f"impact: {original_impact} -> {result.output.impact}")
        if result.output.cvss3_score != original_score:
            changes.append(
                f"cvss3_score: {original_score} -> {result.output.cvss3_score}"
            )

        metric_changed: list[str] = []
        metric_unchanged: list[str] = []
        new_vector = result.output.cvss3_vector or ""
        if new_vector != original_vector:
            metric_changed, metric_unchanged = self._diff_vector_metrics(
                original_vector, new_vector
            )
            changes.extend(metric_changed)

        metric_instructions = ""
        if metric_changed:
            metric_instructions = (
                f"\n\nMetrics that changed: {', '.join(metric_changed)}. "
                "Update ONLY the justifications for these metrics."
            )
            if metric_unchanged:
                metric_instructions += (
                    f"\nDo NOT modify the justifications for: "
                    f"{', '.join(metric_unchanged)}."
                )

        # Build a concise CVE context block so the revision LLM can write
        # technically accurate justifications without the full conversation.
        context_block = ""
        if cve_context:
            title = cve_context.get("title", "")
            description_text = (
                cve_context.get("cve_description")
                or cve_context.get("comment_zero")
                or cve_context.get("description", "")
            )
            components = cve_context.get("components", [])
            parts: list[str] = []
            if title:
                parts.append(f"Title: {title}")
            if components:
                parts.append(f"Components: {', '.join(components)}")
            if description_text:
                parts.append(f"Description: {description_text}")
            if parts:
                context_block = "CVE context:\n" + "\n".join(parts) + "\n\n"

        follow_up = (
            f"{context_block}"
            "Post-processing has adjusted your assessment.\n"
            f"Changes: {'; '.join(changes)}\n"
            f"Reconciliation trace: {trace}\n"
            f"{metric_instructions}\n\n"
            "Revise your explanation so the rationale is consistent with "
            "the updated score and impact.  Rewrite the affected sentences "
            "in place — do NOT append a note, disclaimer, or separate "
            "paragraph about the override.  The result must read as a "
            "single coherent explanation.  Keep the same structure and "
            "level of detail.  Return only the revised explanation text."
        )

        override_note = ""
        new_vector = result.output.cvss3_vector or ""
        if new_vector != original_vector or result.output.cvss3_score != original_score:
            override_note = (
                f"\n\nNote: CVSS vector adjusted from "
                f"{original_score} ({original_vector}) to "
                f"{result.output.cvss3_score} ({new_vector})"
                f" during post-processing reconciliation."
            )

        _REVISION_TIMEOUT = llm_prompt_timeout

        try:
            revision_prompt = (
                f"Original explanation:\n{result.output.explanation}\n\n{follow_up}"
            )
            async with llm_sem:
                revision = await asyncio.wait_for(
                    self._run(
                        call_str,
                        revision_prompt,
                        deps=deps,
                        output_type=RevisedExplanationModel,
                    ),
                    timeout=_REVISION_TIMEOUT,
                )
            result.output.explanation = revision.output.explanation + override_note
            logger.info(
                "%s: explanation revised after post-processing adjustments", call_str
            )
            return True
        except TimeoutError:
            logger.warning(
                "%s: revision timed out after %ds, keeping original explanation",
                call_str,
                _REVISION_TIMEOUT,
            )
            if override_note:
                result.output.explanation += override_note
            return False
        except Exception as exc:
            logger.warning(
                "%s: failed to revise explanation after post-processing: %s",
                call_str,
                exc,
            )
            if override_note:
                result.output.explanation += override_note
            return False

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        use_kernel_classifier = get_settings().use_kernel_classifier

        use_static = (
            static_context
            and isinstance(static_context, dict)
            and static_context.get("cvss_scores") is not None
        )
        resolved_static_context = static_context if use_static else None
        is_kernel = False

        if use_kernel_classifier:
            components = []
            if isinstance(static_context, dict):
                components = static_context.get("components") or []

            # Only fetch from OSIDB directly when the agent has the OSIDB
            # toolset; otherwise let the LLM call it through its own tools.
            if not components and self.agent.name == "RHFeatureAgent":
                cve_data = await osidb_tool.cve_retrieve(cve_id)
                components = cve_data.components

            is_kernel = is_kernel_component(components)

        # Eagerly run the kernel classifier so the result is available on
        # deps for both the tool fast-path and post-processing.
        # kernel_impact_tool will return this cached result instantly when
        # the LLM calls it.
        if use_kernel_classifier and is_kernel:
            from aegis_ai.toolsets.tools.kernel_classifier import kernel_impact_classify

            pre_clf = await kernel_impact_classify(
                cve_id, static_context=resolved_static_context
            )
        else:
            pre_clf = None

        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=[
                "affects",
                "impact",
                "mitigation",
                "rh_cvss_score",
                "statement",
            ],
            static_context=resolved_static_context if use_static else None,
            is_kernel_cve=is_kernel,
            classifier_attempted=use_kernel_classifier and is_kernel,
        )
        if pre_clf is not None:
            deps.classifier_result = pre_clf

        output_schema = SuggestImpactModel.model_json_schema()
        if not is_kernel:
            for kernel_only_field in (
                "classifier_disagreement_rationale",
                "kernel_manual_review",
                "kernel_nullptr_related",
                "kernel_btrfs_context",
            ):
                output_schema.get("properties", {}).pop(kernel_only_field, None)
        else:
            props = output_schema.get("properties", {})
            required = output_schema.setdefault("required", [])
            for kernel_required_field in (
                "kernel_manual_review",
                "kernel_nullptr_related",
                "kernel_btrfs_context",
            ):
                if (
                    kernel_required_field in props
                    and kernel_required_field not in required
                ):
                    required.append(kernel_required_field)

        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and derive a CVSS v3.1 base vector and score with metric-by-metric rationale from the perspective of Red Hat customers. Based on the score, select the impact (LOW/MODERATE/IMPORTANT/CRITICAL).",
            goals="""
                - Return exactly one CVSS:3.1 base vector and score consistent with each other.
                - Provide short reasoning for each base metric (AV, AC, PR, UI, S, C, I, A).
                - Prefer AV:L for local-only flaws; use AV:N only if remote/network reachable without local access; AV:A when limited to same-link/adjacent network; AV:P for physical.
                - For DoS-only flaws, emphasize A over C/I; for LPE, emphasize PR>UI and I (and C when secrets are exposed).
                - Do not base metric choices on which RH products are affected; reason from technical preconditions and exploit mechanics.
                - Pick impact (Critical/Important/Moderate/Low) from the computed score.
            """,
            rules=RULES_KERNEL if is_kernel else self._RULES_BASE,
            context=_build_cve_input(cve_id, static_context),
            output_schema=output_schema,
        )

        run_kwargs: dict = {"deps": deps, "output_type": SuggestImpactModel}

        if is_kernel:
            from aegis_ai.toolsets import kernel_extra_toolset

            run_kwargs["toolsets"] = [kernel_extra_toolset]

        result = await self.guarded_run(prompt, **run_kwargs)
        call_str = f"{self.__class__.__name__}({cve_id})"
        classifier_result = deps.classifier_result

        original_score = result.output.cvss3_score
        original_vector = result.output.cvss3_vector or ""
        original_impact = result.output.impact

        result.output._original_llm_impact = original_impact
        result.output._original_llm_score = original_score
        result.output._original_llm_vector = original_vector

        # Compute independent ActionableScore before deterministic reconciliation.
        if is_kernel:
            kernel_context = await _ensure_kernel_context_for_second_opinion(
                str(cve_id), deps, call_str
            )
            logger.info(
                "%s: SECOND_OPINION kernel context=%s chars",
                call_str,
                len(kernel_context or ""),
            )
            second_opinion = await self._experimental_kernel_second_opinion(
                result, deps, classifier_result, call_str, kernel_context
            )
        else:
            second_opinion = None

        # ------------------------------------------------------------
        # A.Larkin NN+LLM parity: split synchronous post-processing so the
        # asynchronous request_llm_kpanic-equivalent runs AFTER H1-H15/AS1-AS7
        # but BEFORE kpanic CVSS normalization.
        # ------------------------------------------------------------
        SuggestImpact.post_process_cvss(result.output, call_str)
        pre_reconcile_impact = result.output.impact

        trace = SuggestImpact.reconcile_severity(
            result.output,
            call_str,
            classifier_result=classifier_result,
            second_opinion=second_opinion,
        )

        kpanic_review = await self._experimental_kernel_kpanic_review(
            result,
            deps,
            classifier_result,
            second_opinion,
            call_str,
            kernel_context,
        )

        if kpanic_review is not None:
            kpanic_trace = apply_kpanic_llm_review(
                result.output,
                call_str,
                kpanic_review,
                second_opinion=second_opinion,
            )
            if kpanic_trace:
                trace = f"{trace}; {kpanic_trace}"

        afterpushed_review = await self._experimental_kernel_afterpushed_review(
            result,
            deps,
            classifier_result,
            second_opinion,
            call_str,
            kernel_context,
        )
        if afterpushed_review is not None:
            afterpushed_trace = apply_afterpushed_llm_review(
                result.output,
                call_str,
                afterpushed_review,
                second_opinion=second_opinion,
            )
            if afterpushed_trace:
                trace = f"{trace}; {afterpushed_trace}"

        # NEW56: AS7 is now a post-review, fail-closed auto-close decision.
        # ActionableScore only makes a case eligible; the always-run specialized
        # review must independently and positively approve LOW, and deterministic
        # contradiction guards can still veto it.
        deferred_low_trace = apply_deferred_low_review(
            result.output,
            call_str,
            kpanic_review,
            classifier_result,
            second_opinion=second_opinion,
        )
        if deferred_low_trace:
            trace = f"{trace}; {deferred_low_trace}"

        # NEW58: LOW is destructive/auto-closing, so the independent specialized
        # review gets a final deterministic veto even when an earlier H/AS path
        # reached LOW before NEW56's deferred-low gate.  A strong manual-review
        # verdict restores MODERATE7; a strong LOW-unsafety verdict alone restores
        # ordinary MODERATE.  This invariant never promotes to IMPORTANT.
        final_low_safety_trace = apply_final_low_safety_invariant(
            result.output,
            call_str,
            kpanic_review,
        )
        if final_low_safety_trace:
            trace = f"{trace}; {final_low_safety_trace}"

        # NEW54: final operational-state consistency invariant.
        #
        # kpanic_marked is an operational MODERATE7/manual-review marker, not
        # an assertion that a factual kernel panic was proven.  After all
        # specialized reviews have had their vote, LOW + a live marker is an
        # internally inconsistent representation.  Restore MODERATE7 here;
        # this is not a new vulnerability-severity heuristic.
        if (
            result.output.impact == "LOW"
            and getattr(result.output, "_kernel_kpanic_marked", False) is True
        ):
            result.output.impact = "MODERATE"
            invariant_trace = "NEW54:OPERATIONAL_KPANIC_FLOOR_LOW_TO_MODERATE7"
            trace = f"{trace}; {invariant_trace}"
            logger.info(
                "%s: %s",
                call_str,
                invariant_trace,
            )

        override_trace = apply_kpanic_cvss_override(
            result.output,
            call_str,
            classifier_result,
            second_opinion=second_opinion,
        )
        if override_trace:
            trace = f"{trace}; {override_trace}"
        elif result.output.impact != pre_reconcile_impact:
            # NEW49.3: when downstream reconciliation lowers the impact and the
            # independently parsed ActionableScore CVSS belongs to that final
            # impact band, export that selected score/vector instead of leaving
            # the stale primary IMPORTANT CVSS on a MODERATE result.
            #
            # This is deliberately narrow: it does not invent a vector and it
            # does not alter severity.  Missing, malformed, or band-inconsistent
            # selected CVSS falls back to the historical alignment behavior.
            selected_cvss_applied = False
            if second_opinion is not None:
                selected_score = getattr(second_opinion, "cvss_selected_score", None)
                selected_vector = getattr(second_opinion, "cvss_selected_vector", None)
                if selected_score is not None and selected_vector:
                    try:
                        selected_vector = str(selected_vector).strip()
                        selected_score_from_vector = float(
                            cvss.CVSS3(selected_vector).scores()[0]
                        )
                        selected_band = score_to_band(selected_score_from_vector)
                        if selected_band == result.output.impact:
                            old_score = result.output.cvss3_score
                            old_vector = result.output.cvss3_vector
                            result.output.cvss3_score = str(selected_score_from_vector)
                            result.output.cvss3_vector = selected_vector
                            selected_cvss_applied = True
                            sync_trace = (
                                "selected_cvss_sync_after_downgrade("
                                f"{old_score}/{old_vector}->"
                                f"{result.output.cvss3_score}/{selected_vector})"
                            )
                            trace = f"{trace}; {sync_trace}"
                            logger.info(
                                "%s: synchronized downgraded impact %s with "
                                "second-opinion selected CVSS %s (%s)",
                                call_str,
                                result.output.impact,
                                result.output.cvss3_score,
                                result.output.cvss3_vector,
                            )
                        else:
                            logger.info(
                                "%s: selected CVSS %.1f is band %s, not final "
                                "impact %s; keeping historical alignment path",
                                call_str,
                                selected_score_from_vector,
                                selected_band,
                                result.output.impact,
                            )
                    except Exception as exc:
                        logger.warning(
                            "%s: selected CVSS unavailable for downgrade sync; "
                            "keeping historical alignment path: %s",
                            call_str,
                            exc,
                        )

            if not selected_cvss_applied:
                SuggestImpact.align_score_to_impact(result.output, call_str)

        # Older ver before ActionableScore check (that was much simplified):
        #        if (
        #            second_opinion is not None
        #            and result.output.impact == "IMPORTANT"
        #            and second_opinion.recommended_impact == "MODERATE"
        #            and not second_opinion.useful_non_crash_primitive
        #            and second_opinion.confidence >= 0.70
        #        ):
        #            logger.info(
        #                "%s: SECOND_OPINION APPLY IMPORTANT -> MODERATE "
        #                "(panic_dominant=%s confidence=%.2f rationale=%s)",
        #                call_str,
        #                second_opinion.panic_dominant,
        #                second_opinion.confidence,
        #                second_opinion.rationale,
        #            )
        #
        #            result.output.impact = "MODERATE"
        #
        #            # Keep CVSS consistent with the newly lowered impact.
        #            # For now we deliberately do NOT invent a new vector here.
        #            SuggestImpact.align_score_to_impact(result.output, call_str)
        #
        #            trace = (
        #                f"{trace}; experimental_second_opinion:"
        #                f"IMPORTANT->MODERATE"
        #            )

        # end of "Inserted by A.Larkin, dirty hack"

        impact_changed = result.output.impact != original_impact
        vector_changed = result.output.cvss3_vector != original_vector
        guardrail_fired = classifier_result is not None and (
            impact_changed or vector_changed
        )
        if guardrail_fired:
            result.output._explanation_revised = await self._revise_explanation(
                result,
                original_score,
                original_impact,
                original_vector,
                trace,
                call_str,
                deps=deps,
                cve_context=resolved_static_context,
            )

        result.output._classifier_diagnostics = classifier_result
        result.output._reconciliation_trace = trace

        # Export the final mutable Perl-compatible KPANIC state.
        if classifier_result and isinstance(classifier_result, dict):
            final_kpanic = getattr(result.output, "_kernel_kpanic_marked", None)
            if final_kpanic is None:
                active = classifier_result.get("active_features", [])
                exported_flags = {
                    _FLAG_TO_LABEL[f] for f in active if f in _FLAG_TO_LABEL
                }
            else:
                exported_flags = {"kpanic"} if final_kpanic else set()

                # NEW26_FINAL_OPERATIONAL_KPANIC_DIAGNOSTICS_SYNC
                # At this late export boundary reconciliation and both LLM
                # false-positive reviews are complete. Keep all unrelated
                # classifier features, but normalize panic markers to the final
                # Perl-compatible operational KPANIC state so diagnostic
                # Patch Flags consumers see the same final state.
                active = list(classifier_result.get("active_features", []) or [])
                active = [
                    feature
                    for feature in active
                    if feature not in {"kernel_panic", "kernel_panic_plus_uaf"}
                ]
                if final_kpanic:
                    active.append("kernel_panic")
                classifier_result["active_features"] = active

                logger.info(
                    "%s: final operational KPANIC diagnostics sync: "
                    "kpanic_marked=%s active_features=%s",
                    call_str,
                    "YES" if final_kpanic else "NO",
                    active,
                )

            result.output._flags = sorted(exported_flags)

        return result


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=["cwe_id"],
            static_context=static_context,
        )

        prompt = AegisPrompt(
            user_instruction="From the CVE JSON, identify the most specific CWE that matches the directly exploitable software weakness. Ignore any pre-labeled CWE.",
            goals="""
                - Prefer the most specific CWE over broad parents.
                - Prefer the directly observable/exploitable weakness over abstract root causes. For example, if a missing return-value check leads to a NULL pointer dereference, prefer CWE-476 (NULL Pointer Dereference) over CWE-252 (Unchecked Return Value).
                - Distinguish between similar-sounding weaknesses. For example, a NULL pointer dereference (CWE-476) is not the same as an uninitialized pointer dereference (CWE-824). Match the CWE to the actual weakness described, not to a superficially similar one.
                - Return a short explanation and confidence.
            """,
            rules="""
                - Retrieve and summarise additional context strictly from vulnerability reference URLs and CWE tool outputs.
                    - Prefer mitre_cwe tools (retrieve_allowed_cwe_ids, search_cwes, retrieve_cwes) for CWE selection and definitions.
                    - Use github mcp tool to resolve vulnerability reference URLs if present.
                    - Do NOT call external_references_tool — it returns bulk content that is not needed for CWE classification.
                    - Avoid using general-purpose web search or encyclopedic tools for CWE selection unless references are insufficient.
                - Identify set of candidate CWEs - always use the mitre cwe tool retrieve_allowed_cwe_ids to filter candidate CWE list.
                    - Analyze vulnerability, identify CWE that matches root cause of weakness, being careful about memory management and buffer overflows.
                    - Perform search using mitre cwe tool cwe_searches to identify candidate CWEs (perform cwe_searches with 2-3 different queries).
                - Use mitre cwe retrieve_cwes tool to get additional information on candidate CWEs.
                - Select the top 2-3 most applicable CWEs (preference on applicability and higher similarity score) from the final set of candidate CWEs.
                - The final list of suggested CWEs should be ranked from most to least applicable to the vulnerability. For example, the first item in the array should be the most applicable CWE based on entire vulnerability analysis.
                Output should include:
                - cwe: Return ordered list of top 2–3 applicable CWE IDs (ex. ["CWE-94"])
                - explanation: 1–2 sentences connecting CVE details to the CWE.
                - confidence: [0.00..1.00].
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=SuggestCWEModel.model_json_schema(),
        )

        run_kwargs: dict = {"deps": deps, "output_type": SuggestCWEModel}
        result = await self.guarded_run(prompt, **run_kwargs)
        # Post-process: filter out any disallowed CWE IDs (guardrail in case LLM misses rules)
        await cwe_manager.initialize()
        allowed_cwe_ids = set(cwe_manager.get_allowed_cwe_ids())
        suggested_cwes = result.output.cwe
        filtered_out = [cwe for cwe in suggested_cwes if cwe not in allowed_cwe_ids]
        if filtered_out:
            logger.warning(
                f"{self.__class__.__name__}({cve_id}): filtering out disallowed CWE IDs: {filtered_out}"
            )
            result.output.cwe = [
                cwe for cwe in suggested_cwes if cwe in allowed_cwe_ids
            ]
        return result


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(cve_id=str(cve_id), exclude_osidb_fields=[])
        prompt = AegisPrompt(
            user_instruction="Examine the CVE JSON and identify any PII (names, emails, phone numbers, IDs, IPs, health/genetic info, etc.).",
            goals="""
                - Traverse all fields; consider both keys and values.
                - Prefer precise matches; avoid speculation.
            """,
            rules="""
                Output rules:
                - explanation: If PII is found, provide a bulleted list using the '-' character. Each item must be in the format: PII type: "exact string". Example: - Gender: "male".
                  - The PII type must be a concise description (e.g., "Gender", "Race", "Email Address", "Phone Number").
                  - The "exact string" must be the literal value from the JSON.
                  - Create a new bullet point for each unique instance of PII found.
                  - If no PII is found, this field should be an empty string ("").
                - confidence: [0.00..1.00].
                - contains_PII: true if any PII found, else false.
                
                Only report PII present in the JSON. Do not add extra text or line breaks like \n inside items.
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=PIIReportModel.model_json_schema(),
        )
        return await self.guarded_run(prompt, deps=deps, output_type=PIIReportModel)


class SuggestDescriptionText(Feature):
    """Based on current CVE information and context suggest a description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=["title", "cve_description"],
            static_context=static_context,
        )
        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and suggest the CVE description and title to be brief, clear, and accurate. If missing, propose them. Write for a non-technical/executive audience (e.g., a CISO) using plain English; avoid jargon and define unavoidable terms briefly.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
                - The description should be 2–5 sentences and easy to read.
                - The title should briefly summarize the core issue in one line; keep headline-level detail only (do not mirror the full description).
            """,
            rules="""
                - After calling osidb_flaw_tool, pass the flaw's reference URLs to external_references_tool to retrieve additional context about the vulnerability from upstream advisories.
                'description': one short paragraph.
                - Begin with: "A flaw was found in <component>."
                - Clearly state: who can exploit the flaw (e.g., a remote attacker, a local user, a malicious server), how it can be exploited (method/conditions), and the concrete consequences.
                - Include the vulnerability type when clear, the affected component, the trigger/cause, and the primary impact.
                - Highlight the most important consequence first. Prefer domain phrases such as "arbitrary code execution", "privilege escalation", "information disclosure", or "Denial of Service (DoS)".
                - Use plain English; avoid deep implementation jargon. If a function or symbol name is central to exploitation, you may mention a single example and explain it briefly.
                - If a term or acronym is needed, briefly define it and expand the acronym in parentheses on first use.
                - Do not include product/version lists, package names, or mitigation/update guidance. Never copy version numbers or version ranges from the CVE input (e.g., "2.442 through 2.554", "prior to 0.5.6") into the description — describe the flaw generically.
                - Do not mention exploit availability or public disclosure status (e.g., "The exploit has been publicly disclosed").
                - Avoid generic CIA boilerplate; name the concrete impact (e.g., data disclosure, code execution, denial of service).
                - When upstream or reference text in the CVE is well written, prefer clarity and professional advisory tone over adding redundant phrasing.
                - Ambiguity and uncertainty:
                  - Do NOT invent a specific component, function, trigger, CWE, or impact if the source data and references do not clearly support it.
                  - If a single component or trigger cannot be reliably identified, use neutral wording (e.g., "in the affected component") and describe the mechanism at a high level.
                  - Prefer calibrated phrasing when evidence is weak (e.g., "may allow", "can enable") rather than asserting specifics.
                  - Never mention CWE identifiers or CWE category names (e.g., "CWE-79", "CWE-835", "Loop with Unreachable Exit Condition") in the description — CWE classification is handled separately.
                  - Only include a precise impact (e.g., "arbitrary code execution", "privilege escalation") when it is well-supported; otherwise, use a generic but accurate type (e.g., "input validation vulnerability", "memory corruption vulnerability") or simply "vulnerability".
                'title': <= 20 words, summarize the description; include product/component and vulnerability type or consequence.
                - Style: "<Component>: <primary consequence> via <trigger/cause>" when applicable.
                - Prefer one primary consequence in the title (the worst plausible or the one the advisory emphasizes). Avoid stacking multiple unrelated impact types (e.g. several "and" clauses for different CIA outcomes); use one umbrella phrase in the title and put nuance in the description.
                - The title may include a specific function or primitive if it is the salient trigger; avoid extraneous implementation details and avoid stuffing multiple impact dimensions into the title—those belong in the description.
                - If the trigger is unclear, omit the "via <trigger/cause>" clause. If the component is unclear, name the project/product or keep a consequence-first title without fabricating specifics.
                - Strictly exclude versions: never include any version numbers or ranges (e.g., "5.0.0", "v2", "2.x", "9.x and earlier") in the title.
                - Keep it focused and professional.
                - 'description' and 'title' need to be consistent with each other.
                - Never output meta-diagnostic text such as "information is inconsistent", "insufficient data", "cannot determine", or similar. Provide the best-supported description instead with calibrated confidence.
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=SuggestDescriptionModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestDescriptionModel
        )


class SuggestStatementText(Feature):
    """Based on current CVE information and context suggest a statement and mitigation."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=["statement", "mitigation"],
            static_context=static_context,
        )
        NO_MITIGATION_TEXT = (
            "Mitigation for this issue is either not available or the currently available "
            "options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, "
            "applicability to widespread installation base, or stability."
        )

        prompt = AegisPrompt(
            user_instruction=f"Analyze the provided CVE context ({cve_id}) and generate a Red Hat specific Statement and Mitigation.",
            goals="""
            - Provide two fields tailored for Red Hat products:
              1) Suggested Statement: brief rationale of impact in RH context
              2) Suggested Mitigation: practical configuration or operational workaround tailored to Red Hat
            - Keep outputs concise and consistent; avoid contradiction between fields.
            """,
            rules=f"""
            - After calling osidb_flaw_tool, pass the flaw's reference URLs to external_references_tool to retrieve detailed impact context from upstream advisories and GHSAs.
            ### STATEMENT (suggested_statement)
            - Focus on impact and RH relevance (deployment model, defaults, hardening).
            - Start with a concise severity-and-why sentence tailored for Red Hat that is consistent with the provided 'impact' field if available:
              - If 'impact' is present in context, reuse that label but in Title Case (Low/Moderate/Important/Critical) and do not contradict it.
              - If 'impact' is not present, avoid assigning an explicit severity label; describe impact qualitatively instead.
            - Add value beyond the CVE description and public comments: explain *why* that severity label fits the risk (e.g., why Important rather than Moderate), not a restatement of comment #0 alone.
            - When you include an explicit severity label (Low/Moderate/Important/Critical), add at least one short clause that justifies that band (e.g. local-only vs remote, prerequisites, blast radius, or why not the next lower severity)—not only a description of the bug mechanics.
            - Differentiate from the CVE description: lead with Red Hat deployment context (defaults, exposure on typical installs) where possible; do not reuse the same sentence structure or chain of nouns as cve_description (reorder ideas and change phrasing so the statement is not a light paraphrase).
            - Explain briefly why impact applies (e.g., feature disabled by default, needs uncommon configuration, requires physical access, short-lived CLI use).
            - Applicability without duplicating the advisory "Affects" list:
              - Do not paste product/version matrices; readers can see those elsewhere. At most one short clause when defaults or preconditions are essential (e.g., "disabled by default on RHEL 8 and 9").
              - If the vulnerability requires a feature that is disabled by default on common RH releases, say so briefly; avoid enumerating every unaffected release unless a single contrast is needed.
              - If exploit requires physical access or specialized hardware, highlight that requirement; mention if virtualized/emulated devices could still enable exploitation.
            - When applicable, note preconditions and what is not affected (e.g., roles, disabled-by-default features) without turning the statement into a component version manifest.
            - Must NOT:
              - Duplicate the CVE description verbatim or copy any sentence or 7+ consecutive words from it; paraphrase and focus on RH-specific context.
              - Lead with or emphasize upstream component version strings (e.g., "Foo 1.2.3"); severity narrative comes first.
              - Include code-level details or command examples.
              - Mention mitigation steps or software updates/patching.
            - Style: 2–4 concise sentences, < 1000 characters total.
            
            ### MITIGATION (suggested_mitigation)
            - **Definition:** A configuration or operational control that reduces exposure without patching (e.g., config file, environment variable or feature toggle, sysctl, service disable, or removing optional packages). Prefer a conservative, documented mitigation over declaring that none exists.
            - **Prohibitions:**
                - **NEVER** suggest updating/patching software.
                - **NEVER** invent config flags or commands.
                - **NEVER** use the term 'update'.
                - **NEVER** suggest dangerous commands (`rm -rf`, `chmod 777`, disabling SELinux globally) without explicit, dire warnings.
            - **Decision process (use before considering fallback):**
                1. Identify what exposes the vulnerable component in RH context (network daemon, optional plugin/format, kernel module/driver, desktop-only feature).
                2. Check for documented, supported controls to reduce exposure: restrict network reachability, disable optional features/plugins/filters, sandbox, or blacklist/avoid autoloading kernel modules.
                3. If any safe, documented configuration or operational control exists, provide it even if it only partially reduces risk; clearly note caveats.
                4. Only if no such control exists or the CVE does not affect RH products, proceed to the fallback.
            - **Structure:**
                1. Summary of action ("Disable the X service").
                2. Command examples (`sysctl`, `systemctl`).
                3. Caveats ("This may impact performance").
                4. Always warn if there is a potential for reload and restarts (If CVE is related to a service and mitigation provides concrete command line instructions, always provide a warning)
            - Prefer configuration-only or operational hardening patterns when applicable:
                - Limit service exposure: restrict access to trusted networks, apply rate limiting or firewall rules, and enable protocol validation features if available (e.g., DNSSEC for resolvers).
                - Disable optional features required to trigger the flaw: use configuration or environment toggles to turn off risky engines or modes; remove optional packages that provide the risky component if not needed.
                - Web content engines or embedded browsers (e.g., WebKitGTK): advise avoiding untrusted web content; if exploitation depends on JIT, disable it via a documented toggle when available (example for WebKitGTK: set environment variable JavaScriptCoreUseJIT=0 on affected systems).
                - If exposure is introduced by optional desktop/GUI packages, list common packages that pull in the vulnerable component and suggest removing them if not needed; clearly warn that removing these may also remove GNOME or related packages and break functionality; note that servers remain usable via terminal.
                - For components that process untrusted content (browsers, renderers, document viewers), advise operational controls such as avoiding untrusted content and sandboxing. If a JIT or optional execution engine can be disabled via a documented environment variable or config flag, suggest disabling it (e.g., an environment variable toggle).
                - Kernel driver vulnerabilities: prevent autoloading of the affected module via an /etc/modprobe.d rule (install/blacklist); note that a restart or service reload may be required and may impact functionality.
                - Network daemons (e.g., CUPS, dnsmasq, httpd): restrict service to localhost or trusted networks, disable remote administration, and firewall the relevant port(s) if feasible in your environment.
            - **Fallback:** Use only after the decision process above confirms that no safe, documented configuration or operational control exists in Red Hat products, or if the CVE does not affect Red Hat products (e.g., Windows-only). If any partial risk reduction is possible (e.g., firewalling, limiting to localhost, disabling optional plugins/filters, sandboxing, or blacklisting a kernel module), DO NOT use the fallback. When applicable, YOU MUST USE EXACTLY THIS TEXT:
              "{NO_MITIGATION_TEXT}"
            - Length: < 2000 characters.
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=SuggestStatementModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestStatementModel
        )


def _has_sufficient_static_context(static_context: Any) -> bool:
    """True when static_context has enough data to infer components without OSIDB."""
    if not static_context or not isinstance(static_context, dict):
        return False
    desc = (
        static_context.get("comment_zero")
        or static_context.get("cve_description")
        or ""
    )
    return bool(desc)


class SuggestAffectedComponents(Feature):
    """Infer affected components from CVE data using all available OSIDB fields."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        use_static = _has_sufficient_static_context(static_context)
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=["affects", "components"],
            static_context=static_context if use_static else None,
        )
        prompt = AegisPrompt(
            user_instruction="From the provided CVE data (title, description, statement, references, affects, comments, etc.), identify the affected software component(s). "
            "Use the OSIDB tool to retrieve flaw data when cve_id is provided; when full context is already provided, the tool returns that data. Leverage all available fields to infer components.",
            goals="""
                - From all available CVE/OSIDB data (title, comment_zero, description, statement, mitigation, comments, references, affects, cvss_scores, cwe_id, impact), identify the affected software component(s).
                - List component names (package names) in the output 'components' field.
                - Where a Package URL (PURL) is identified use the name part of the PURL, without any namespace or type prefix. Exception: for Maven packages, always include the groupId and use groupId/artifactId format with a forward slash separator (e.g. 'com.mchange/mchange-commons-java' not 'mchange-commons-java', 'org.traccar/traccar' not 'org.traccar:traccar', 'org.apache.sshd/sshd-core' not just 'sshd-core'). Similarly, for PHP Composer packages, always include the vendor and use vendor/package format (e.g. 'phpseclib/phpseclib' not 'phpseclib').
                - Never prefix component names with ecosystem identifiers: no 'python-', 'nodejs-', or 'rubygem-' prefixes. Use the bare package name (e.g. 'cryptography' not 'python-cryptography', 'dotenv' not 'python-dotenv', 'axios' not 'nodejs-axios', 'rack' not 'rubygem-rack'). Strip the prefix even when the upstream project name includes it (e.g. PyPI package 'python-dotenv' → 'dotenv'). Only strip the exact prefixes listed above — 'node-' is NOT an ecosystem prefix (e.g. npm package 'node-forge' → 'node-forge', not 'forge'). Exception: keep the 'rust-' prefix — it is a Red Hat distro naming convention, not an ecosystem prefix (e.g. 'rust-openssl', 'rust-coreutils').
                - For Go packages outside stdlib, always use the full module path as the component name. This applies to github.com/ packages (e.g. 'github.com/containerd/containerd' not 'containerd', 'github.com/go-acme/lego' not 'lego') and golang.org/x/ packages (e.g. 'golang.org/x/net/html' not 'net/html', 'golang.org/x/oauth2/jws' not 'oauth2/jws'). Strip Go major-version suffixes (/v2, /v3, /v7, etc.) from the module path (e.g. 'github.com/oauth2-proxy/oauth2-proxy' not 'github.com/oauth2-proxy/oauth2-proxy/v7').
                - If the component is from the Python standard library, use 'python' as the component name.
                - If the component is from the Go standard library, keep the full stdlib path (e.g. 'crypto/internal/nistec', 'crypto/x509', 'cmd/go', 'net/http/internal') and return it first in the components array in addition to the component 'golang'.
                - Use Red Hat distribution package names, not upstream project or product names. Examples: Linux kernel → 'kernel', Google Chrome/Chromium (including sub-components like V8, Blink, ANGLE, PDFium, Skia, DevTools, WebGL, WebML, Compositing) → 'chromium-browser', MySQL Server → 'mysql', uutils/coreutils → 'rust-coreutils', OpenSSL Rust bindings → 'rust-openssl', Mbed TLS → 'mbedtls', PowerDNS Recursor → 'pdns-recursor', Roundcube Webmail → 'roundcubemail', OpenPrinting CUPS → 'cups', .NET Framework → 'dotnet', GLib/GLib2 → 'glib', `XML::Parser` → 'perl-xml-parser'. Exception: for Go packages in the golang ecosystem, the full module path (see above) takes precedence over the Red Hat distro name.
                - For the Qt framework, use the Red Hat umbrella component names 'qt', 'qt5', or 'qt6' — not individual sub-module packages (e.g. 'qt6-qtbase', 'qt5-qtconnectivity'). If the CVE affects Qt5, use 'qt5'; if Qt6, use 'qt6'; if Qt in general or both, use 'qt' (or include all applicable: 'qt', 'qt5', 'qt6').
                - Use the source component name, not binary or subpackage names. Examples: Redis → 'redis' not 'redis-server', Apache HTTP Server → 'httpd' not 'httpd-core'.
                - When the CVE title or GitHub repository name differs from the actual package name in the ecosystem registry (npm, PyPI, crates.io, etc.), always use the registry name (e.g. GitHub repo 'node-tar' is published to npm as 'tar' → use 'tar'; GitHub repo 'forge' is published to npm as 'node-forge' → use 'node-forge'; GitHub repo 'tar-rs' is published to crates.io as 'tar' → use 'tar').
                - For proprietary OS kernel vulnerabilities (macOS, iOS, Windows, etc.), use the OS name as the component (e.g. 'macOS', 'iOS', 'Windows'), not 'kernel'. Only use 'kernel' for the Linux kernel.
                - When a vulnerability is in a product's own code (e.g. its shared certificate validation logic), list only the product itself as the affected component. Do not list services, protocols, or features that the product merely uses or integrates (e.g. RouterOS using OpenVPN/CAPsMAN/Dot1x → 'RouterOS' only).
                - Use the bare package/project name, not a descriptive label from the CVE title. Examples: 'musl' not 'musl libc', 'glibc' not 'GNU C Library', 'openssl' not 'OpenSSL library'. This rule is about dropping informal suffixes like 'libc' or 'library' — it does NOT override the ecosystem prefix-stripping rules above (e.g. 'python-dotenv' → 'dotenv' still applies).
                - Never extract product edition abbreviations or suffixes as standalone component names. Tokens like 'CE' (Community Edition), 'EE' (Enterprise Edition), 'SE' (Standard Edition), 'Plus', 'Pro', etc. are product edition qualifiers, not component names. When a product includes an edition suffix (e.g. 'pfSense CE', 'pfSense Plus and CE', 'GitLab EE'), extract only the base product name (e.g. 'pfSense', 'GitLab').
                - Determine which package ecosystem(s) are impacted by the vulnerability. Many components are published to multiple ecosystems (e.g. Redis has pypi, npm, generic); the vulnerability may only affect one. Populate the 'ecosystems' field with one or more of: cargo, golang, npm, pypi, maven, gem, generic, unknown.
                - Provide a concise explanation of the rationale.
            """,
            rules="""
                - Use the osidb_tool with the provided cve_id to retrieve CVE flaw data.
                - Leverage title, description (or comment_zero), statement, references, affects, comments, and any other fields to infer affected components.
                - Use github mcp tool to resolve vulnerability reference URLs if present (e.g. to confirm repo/component names, inspect commit diffs to identify which specific submodules or artifacts are affected).
                - When a CVE mentions an umbrella project (e.g. 'Spring Framework', 'Apache Commons'), do not return the umbrella name — use tools to identify the specific affected Maven artifacts or submodules (e.g. 'org.springframework/spring-webmvc' not 'Spring Framework').
                - If GHSA reference URLs are present in the flaw data, pass them to the osv_dev_ghsa tool to get structured affected-package data (package names, ecosystems, PURLs, version ranges) for component identification.
                - Use osv_dev_ghsa_tool responses to determine impacted ecosystems — the affected[].package.ecosystem field is the most authoritative ecosystem signal.
                - When osv_dev_ghsa_tool returns an affected package name, prefer it over names derived from the CVE title or description — the GHSA package name is the canonical registry identifier.
                - Analyze CVE reference URLs to determine ecosystem: advisory URLs often indicate it (GHSA advisories, npmjs.com, pypi.org links, commit URLs pointing to upstream source). A vulnerability in core source code does not automatically mean every language binding is affected.
                - Use 'unknown' for the ecosystem only when it genuinely cannot be determined from available data.
                - For Go packages outside stdlib, always use the full module path (e.g. 'github.com/external-secrets/external-secrets', 'golang.org/x/net/html'). Never shorten to just the repo name. Strip Go major-version suffixes like /v2, /v7 from the path.
                - Output format: components (list of strings), ecosystems (list of strings), explanation (string), confidence (0.00–1.00).
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=SuggestAffectedComponentsModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestAffectedComponentsModel
        )


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(cve_id=str(cve_id), exclude_osidb_fields=[])
        prompt = AegisPrompt(
            user_instruction="Compare Red Hat CVSS3 vs NVD CVSS3 for the CVE and explain any differences.",
            goals="""
                - Report both base vectors/scores.
                - If identical, explanation must be empty.
            """,
            rules="""
                - Be specific about which metrics drive the difference (AV, AC, PR, UI, CIA).
                - Expand especially on *why* the metrics are different in the Red Hat context.
                - Keep the rationale brief and factual. If no difference, return an empty explanation.
            """,
            context=_build_cve_input(cve_id, static_context),
            output_schema=CVSSDiffExplainerModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=CVSSDiffExplainerModel
        )


class QualityReview(Feature):
    """Score CVE flaw content against a weighted quality rubric (0.0-1.0 scale) evaluated through a Customer Lens framework."""

    _REQUIRED_CATEGORIES = set(CATEGORY_WEIGHTS.keys())  # noqa: RUF012

    _REQUIRED_CRITERIA: set[str] = {  # noqa: RUF012
        # Description - Technical Clarity
        "component_location",
        "vuln_type_mechanics",
        "trigger_conditions",
        "impact_sketch_cia",
        "clarity_for_non_experts",
        # Statement - Technical Clarity
        "presence_per_cvss_rule",
        "structured_formula_present",
        "cvss_context_mentioned",
        "cia_impacts_called_out",
        "threat_nature_scope",
        # Mitigation
        "mitigation_section_exists",
        "fix_version_specifics",
        "actionable_steps",
        "references_linked",
        "risk_reduction_rationale",
        # Grammar & Style
        "spelling_punctuation",
        "sentence_clarity",
        "consistent_terminology",
        "professional_tone",
        "acronyms_defined",
        # Content Ambiguity
        "desc_stmt_match",
        "products_versions_align",
        "no_version_impact_conflicts",
        "terminology_consistent",
        "scope_limits_clear",
        # Technical Value
        "original_non_vague",
        "root_cause_depth",
        "attack_scenario_example",
        "customer_relevance",
        "standards_mapping",
    }

    def _check_output(self, result, deps) -> str | None:
        """Enforce that all rubric criteria across all categories are present and unique."""
        scores = result.output.scores
        expected_count = len(self._REQUIRED_CRITERIA)

        # Check total count
        if len(scores) != expected_count:
            return (
                f"Expected exactly {expected_count} criterion scores, got {len(scores)}. "
                f"QualityReviewModel requires all {expected_count} rubric criteria for a valid overall_score."
            )

        # Check all categories present and no unexpected categories
        found_categories = {s["category"] for s in scores}
        missing_categories = self._REQUIRED_CATEGORIES - found_categories
        if missing_categories:
            return (
                f"Missing scores for categories: {', '.join(sorted(missing_categories))}. "
                f"You must include criterion scores for all {len(self._REQUIRED_CATEGORIES)} rubric categories."
            )
        unexpected_categories = found_categories - self._REQUIRED_CATEGORIES
        if unexpected_categories:
            return (
                f"Unexpected categories: {', '.join(sorted(unexpected_categories))}. "
                f"Only these categories are valid: {', '.join(sorted(self._REQUIRED_CATEGORIES))}."
            )

        # Check all criterion IDs present and unique
        found_criteria = {s["criterion_id"] for s in scores}
        if len(found_criteria) != expected_count:
            return (
                f"Found {len(found_criteria)} unique criterion IDs but expected {expected_count}. "
                "Each criterion must appear exactly once."
            )
        missing_criteria = self._REQUIRED_CRITERIA - found_criteria
        if missing_criteria:
            return (
                f"Missing criterion IDs: {', '.join(sorted(missing_criteria))}. "
                f"You must score all {expected_count} rubric criteria."
            )

        return None

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        """Run the quality review rubric against the given CVE flaw content."""
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=[],
            static_context=static_context,
        )

        prompt = AegisPrompt(
            user_instruction=(
                f"Review the quality of CVE flaw content for {cve_id}. "
                "Score it against the quality rubric and evaluate through the Customer Lens framework. "
                "Use the OSIDB tool to retrieve all flaw data. "
                "Assess the existing content — do not generate new descriptions or statements unless scoring reveals critical gaps. "
                "Return your response as a single JSON object matching the output schema."
            ),
            goals="""\
- Score the flaw content against a weighted rubric with 6 categories (5 criteria x 2 points each = 10 raw points per category, weighted to a 0.0-1.0 final score).
- Category weights: Description 20%, Statement 25%, Mitigation 10%, Grammar 15%, Content Ambiguity 15%, Technical Value 15%.
- Evaluate content through the Customer Lens: determine whether three customer personas (Ops/Sysadmin, Security/CISO, Compliance/Auditor) can answer their core questions from the existing content.
- Identify strengths, critical gaps, and actionable recommendations.
- When statement or mitigation content scores poorly, provide suggested rewrites.
- Assess whether the flaw content adds value beyond what customers can find in public CVE databases.
""",
            rules="""\
### RUBRIC CATEGORIES

IMPORTANT: You MUST score ALL 30 criteria below (5 per category x 6 categories). Do not skip any category or criterion. Keep each justification to one sentence. Use the exact criterion_id values shown below.

Score each criterion 0 (missing/wrong), 1 (partial), or 2 (fully met).

**Category 1: Description - Technical Clarity** (up to 10 points)
Evidence fields: description, affected_components, source_refs, cvss_vector, attack_scenario

- component_location: Component & Location Identified
  2 = Names the affected component AND precise code location (file and/or function).
  1 = Component identified but no precise code location OR only a module path.
  0 = No clear component or location identified.
  Look for: file/function names (e.g., foo.c:bar()), package/module identifiers (e.g., org.apache.cxf...)

- vuln_type_mechanics: Vulnerability Type & Mechanics
  2 = States the type (e.g., use-after-free) AND explains why/how it occurs.
  1 = States the type but not the mechanics (only labels).
  0 = No type or incorrect type.
  Look for: named class (buffer overflow, UAF, SQLi), short cause explanation.
  Example: "Use-after-free due to double kfree on tcx_entry after clsact detach."

- trigger_conditions: Trigger Conditions
  2 = Explains the inputs/state that trigger the flaw (e.g., malformed header, specific qdisc sequence).
  1 = Hints at a trigger but lacks specifics.
  0 = No trigger described.
  Look for: specific input patterns, preconditions (auth, config, feature flag).

- impact_sketch_cia: Impact Sketch (CIA)
  2 = Links to confidentiality, integrity, or availability clearly (e.g., info leak, code exec, DoS).
  1 = Mentions impact but not mapped to CIA explicitly.
  0 = No impact described.
  Look for: CIA words or synonyms, RCE/DoS/data exposure mapping.

- clarity_for_non_experts: Clarity for Non-Experts
  2 = Uses simple language/analogy or example without losing accuracy.
  1 = Mostly clear but heavy jargon or long sentences.
  0 = Confusing/overly technical.
  Look for: plain language explanation, short sentences, limited jargon.

**Category 2: Statement - Technical Clarity** (up to 10 points)
Evidence fields: statement, cvss_base, cvss_vector, affected_versions

- presence_per_cvss_rule: Presence per CVSS Rule
  2 = Statement present when required (CVSS>=7) or justified absence when <7.
  1 = Statement present but incomplete or too generic.
  0 = Missing when required.
  Rule: If NVD/Red Hat CVSS >= 7.0, a succinct Statement must exist; if <7.0, absence may be acceptable.

- structured_formula_present: Structured Formula Present
  2 = Includes all five elements in a single, concise sentence/paragraph.
  1 = Includes 3-4 elements.
  0 = Includes <=2 elements.
  Formula: component + location + type + trigger + impact.

- cvss_context_mentioned: CVSS Context Mentioned
  2 = Mentions AV/PR/AC (or their plain-language equivalents).
  1 = Hints at context without clarity.
  0 = No context.

- cia_impacts_called_out: CIA Impacts Called Out
  2 = Explicitly maps to C/I/A in statement.
  1 = Impact present but not mapped to CIA.
  0 = No impact.

- threat_nature_scope: Threat Nature/Scope
  2 = Names STRIDE category or explains scope/version differences (e.g., only 1.4-1.6).
  1 = Mentions scope without clarity.
  0 = No scope.

**Category 3: Mitigation** (up to 10 points)
Evidence fields: mitigation, fixed_in, references

- mitigation_section_exists: Mitigation Section Exists
  2 = A clearly labeled Mitigation/Workaround section exists.
  1 = Mitigation is mixed into other text without a clear section.
  0 = No mitigation content.

- fix_version_specifics: Fix/Version Specifics
  2 = Lists patched versions or explicitly states none exist yet.
  1 = Mentions 'update' without versions.
  0 = No fix/version info.

- actionable_steps: Actionable Steps
  2 = Concrete steps (config flags, commands, policy changes).
  1 = High-level advice only.
  0 = No steps.

- references_linked: References Linked
  2 = Links to vendor advisories/KBs/patch notes.
  1 = Mentions external guidance without links/IDs.
  0 = No references.

- risk_reduction_rationale: Risk-Reduction Rationale
  2 = Explains how the step reduces C/I/A impact.
  1 = Implies benefit but not explicit.
  0 = No rationale.

**Category 4: Grammar & Style** (up to 10 points)
Evidence fields: description, statement, mitigation

- spelling_punctuation: Spelling/Punctuation
  2 = No or minor errors; none impede understanding.
  1 = Some errors but mostly understandable.
  0 = Frequent errors impede understanding.

- sentence_clarity: Sentence Clarity
  2 = Clear, concise sentences; avoids run-ons.
  1 = Partly clear but verbose.
  0 = Confusing sentences/run-ons.

- consistent_terminology: Consistent Terminology
  2 = Terminology is consistent across sections.
  1 = Minor inconsistencies.
  0 = Conflicting terms.

- professional_tone: Professional Tone
  2 = Formal, precise tone throughout.
  1 = Occasional informal phrasing.
  0 = Informal/unprofessional tone.

- acronyms_defined: Acronyms Defined
  2 = Acronyms (CVSS, CIA, STRIDE) defined on first use.
  1 = Some acronyms undefined.
  0 = Acronyms not defined.

**Category 5: Content Ambiguity** (up to 10 points)
Evidence fields: description, statement, affected_products, affected_versions

- desc_stmt_match: Description <-> Statement Match
  2 = No contradictions between sections.
  1 = Minor discrepancies.
  0 = Contradictions exist.

- products_versions_align: Products/Versions Align
  2 = Listed products/versions align with described components.
  1 = Partial alignment.
  0 = Misaligned/contradictory.

- no_version_impact_conflicts: No Version/Impact Conflicts
  2 = Version ranges and impacts are consistent.
  1 = Minor inconsistencies.
  0 = Conflicts present.

- terminology_consistent: Terminology Consistent
  2 = Terms (e.g., 'DoS' vs 'hang') used consistently.
  1 = Minor terminology drift.
  0 = Inconsistent terminology.

- scope_limits_clear: Scope & Limits Clear
  2 = States preconditions/limits (auth level, config, platform).
  1 = Implied but not explicit.
  0 = No scope/limits provided.

**Category 6: Technical Value** (up to 10 points)
Evidence fields: description, statement, attack_scenario, cvss_vector

- original_non_vague: Original & Non-Vague
  2 = Original content; avoids boilerplate.
  1 = Some boilerplate.
  0 = Mostly generic.

- root_cause_depth: Root-Cause Depth
  2 = Explains why the flaw occurs (lifecycle/logic/bounds).
  1 = Surface-level cause only.
  0 = No cause explained.

- attack_scenario_example: Attack Scenario/Example
  2 = Provides realistic exploitation scenario or PoC shape.
  1 = Vague scenario.
  0 = No scenario.

- customer_relevance: Customer Relevance
  2 = Connects to user/system risk (e.g., multi-tenant exposure, data class).
  1 = Generic risk.
  0 = No customer angle.

- standards_mapping: Standards Mapping
  2 = Maps to CVSS, CIA, or STRIDE appropriately.
  1 = Partial/implicit mapping.
  0 = No mapping.

### STATEMENT RULES

- If ANY available CVSS base score (Red Hat or NVD) is >= 7.0, a statement MUST exist. If it is absent, this MUST appear in critical_gaps.
- If ALL available CVSS base scores are < 7.0, statement absence is NOT a critical gap.
- Statement quality is evaluated against the structured formula: component + location + type + trigger + impact.

### REJECTED FLAW EXCEPTION

- For rejected flaws (flaw state indicates rejection), do NOT require the 5-part structured formula for the statement.
- Instead, the statement must explain the rationale for rejection. Award full points if the rejection rationale is clear.
- Mitigation MAY be empty or state "No mitigation required." Award full points for mitigation criteria on rejected flaws.

### BOILERPLATE AWARENESS

- Detect and penalize boilerplate content: generic statements that could apply to any CVE without modification.
- Examples of boilerplate: "This vulnerability could allow an attacker to execute arbitrary code", "Users should update to the latest version" without specifics.
- Content that merely restates the CVE description from NVD without adding Red Hat context should score lower on originality.

### CUSTOMER LENS FRAMEWORK

Evaluate whether the content helps three customer personas answer their core questions:

**Ops / Sysadmin** needs:
- Package, service, or configuration names
- Affected and fixed versions
- Executable mitigations
- Operational next steps

**Security / CISO** needs:
- Business risk assessment
- Severity rationale
- Exploit prerequisites
- Exposure likelihood
- Data classes at risk

**Compliance / Auditor** needs:
- CVSS score and vector
- CWE classification
- CIA impact assessment
- STRIDE mapping
- Affected and fixed versions
- Remediation status
- Citeable decision logic

For each review, determine what customers CAN decide, what REMAINS UNCLEAR, and what needs MANUAL context from an analyst.

The three core questions every review must address:
1. Am I exposed?
2. How bad is it for me?
3. What should I do next?

### SUGGESTED REWRITES

- If the statement scores below 6/10 in Category 2, provide a suggested_statement rewrite.
- If the mitigation scores below 6/10 in Category 3, provide a suggested_mitigation rewrite.
- Rewrites should follow the structured formula and address identified gaps.

**Statement rewrite rules:**
- The suggested_statement MUST NOT duplicate the description — it should provide complementary context (severity rationale, scope, prerequisites), not restate the same technical details.
- The suggested_statement MUST NOT mention mitigation steps, software updates, or patching.
- Lead with severity narrative, not upstream component version strings.
- Style: 2-4 concise sentences, < 1000 characters total.

**Mitigation rewrite rules:**
- The suggested_mitigation MUST describe a configuration or operational control that reduces exposure WITHOUT patching (e.g., config flags, sysctl, service disable, firewall rules, removing optional packages).
- NEVER suggest updating, upgrading, or patching software in the mitigation.
- NEVER use the term "update" in the mitigation.
- NEVER invent config flags or commands — only suggest documented, supported controls.
- If no safe, documented mitigation exists, set suggested_mitigation to null rather than providing generic upgrade advice.

### OUTPUT RULES

- Return ALL 30 criterion scores in the "scores" field as a flat list. Each entry must include: category (exact category name from above), criterion_id, score (0-2), and justification (one sentence).
- Do NOT omit any category or criterion. The scores list must contain exactly 30 entries.
- Do NOT compute overall_score or rating — these are auto-computed from your criterion scores.
- Provide the customer_lens assessment with all three lists populated.
- List concrete strengths, critical_gaps, and recommendations (not generic advice).
- The value_add field should assess whether this flaw's content provides information customers cannot find in public CVE databases alone.
- The explanation field should provide a brief summary of the quality review findings, highlighting the most significant strengths and gaps.
- The disclaimer field MUST be exactly: "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert."
""",
            context=_build_cve_input(cve_id, static_context),
            output_schema=QualityReviewModel.model_json_schema(),
        )

        return await self.guarded_run(prompt, deps=deps, output_type=QualityReviewModel)


class SuggestAffectedPackages(Feature):
    """LLM-driven suggestion of source RPM package affectedness."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        # Only use static_context for deps when it contains affects data;
        # otherwise let the OSIDB tool fetch the full flaw record.
        deps_context = (
            static_context
            if isinstance(static_context, dict) and "affects" in static_context
            else None
        )
        deps = feature_deps(
            cve_id=str(cve_id), exclude_osidb_fields=[], static_context=deps_context
        )
        prompt = AegisPrompt(
            user_instruction=(
                "Analyze the CVE and its OSIDB affects data (including PURLs and "
                "product streams) to determine which source RPM packages are affected "
                "by the vulnerability. Use the OSIDB tool to retrieve flaw data."
            ),
            goals="""\
- For each affect entry with a PURL, determine whether the source RPM package is affected by the specific vulnerability described in the CVE.
- Produce a per-package affectedness suggestion with rationale.
- Where possible, identify which internal sub-components within the package are affected (e.g., a specific kernel module, a library within a larger source package).
- Signal low data_quality when the CVE description or affects data is insufficient for confident analysis.
- Provide an overall explanation summarizing the affectedness analysis.
""",
            rules="""\
- Use the osidb_tool with the provided cve_id to retrieve CVE flaw data, including affects with PURLs.
- The affects array is valid in PRE_SECONDARY_ASSESSMENT and later flaw states. In earlier states, the array can be empty or incomplete — this does NOT mean no packages are affected, only that the data is not yet available.
- If the affects array is empty or appears incomplete (e.g., flaw is in an early state like NEW or TRIAGE), set low data_quality and explain that affects data is not yet available.
- If affect entries exist but have null or missing PURLs, treat this as incomplete data — the affected source RPM packages cannot be determined without PURLs. Set low confidence and data_quality, and explain that PURL data is not available.
- Analyze CVE description, references, patches, and comments to understand the technical scope of the vulnerability.
- For each source RPM package identified by PURL in the affects list:
  - Determine whether the package contains the vulnerable code or functionality.
  - Consider the ps_update_stream context — different streams may have different codebases.
  - Provide a concise per-package explanation.
  - If you can identify specific sub-components (kernel modules, libraries, binaries) within the package that are affected, include them in affected_subcomponents.
- Use github MCP tool to inspect commit diffs or repository structure when reference URLs are available.
- The affected field in each AffectedPackageEntry reflects YOUR analysis of whether the package is affected by the vulnerability, considering the technical context.
- Set confidence based on how much technical evidence is available to support your determination.
- Output format: affected_packages (list of AffectedPackageEntry), explanation (string), data_quality, confidence.
""",
            context=_build_cve_input(cve_id, static_context),
            output_schema=SuggestAffectedPackagesModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestAffectedPackagesModel
        )


class QueryAffectedComponents(DeterministicFeature):
    """Deterministic query: return affected components from OSIDB affects data."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        cve = await osidb_tool.cve_retrieve(cve_id)

        entries = [
            AffectedComponentEntry(
                ps_update_stream=affect["ps_update_stream"],
                purl=affect["purl"],
            )
            for affect in cve.affects
            if affect.get("affected") == "AFFECTED"
            and affect.get("purl")
            and affect.get("ps_update_stream")
        ]

        output = QueryAffectedComponentsModel(
            cve_id=cve_id,
            affected_components=entries,
        )

        logger.info(f"QueryAffectedComponents({cve_id}) = {output.printable_outcome()}")
        return DeterministicResult(output)
