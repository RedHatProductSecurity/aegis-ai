import asyncio
import logging
import time
from typing import Any

import cvss

import aegis_ai.toolsets.tools.osidb as osidb_tool
from aegis_ai import get_settings
from aegis_ai.data_models import CVEID
from aegis_ai.features import DeterministicFeature, DeterministicResult, Feature
from aegis_ai.features.cve.data_models import (
    CATEGORY_WEIGHTS,
    AffectedComponentEntry,
    CVEFeatureInput,
    CVSSDiffExplainerModel,
    DownstreamFeatureContext,
    ManifestUsageAnalysis,
    PIIReportModel,
    QualityReviewModel,
    QueryAffectedComponentsModel,
    RevisedExplanationModel,
    SuggestAffectedComponentsModel,
    SuggestAffectedPackagesModel,
    SuggestCWEModel,
    SuggestDescriptionModel,
    SuggestImpactModel,
    SuggestManifestComponentAndStateModel,
    SuggestStatementModel,
)
from aegis_ai.features.cve.downstream import (
    IMPORTER_AFFECT_LIMIT,
    align_manifest_search_keys,
    apply_usage_policy,
    collect_downstream_candidates,
    drop_short_segments_of_kept_modules,
    drop_soft_label_rejects,
    drop_suppressed_short_path_entries,
    ensure_soft_label_keeps,
    post_filter_manifest_entries,
    promote_reference_caller_modules,
    query_bomq_components,
    rejected_soft_label_names,
    resolve_soft_label_rows,
    suppressed_short_path_names,
)
from aegis_ai.features.cve.impact_mappings import SEVERITY_ORDER, score_to_band
from aegis_ai.features.cve.kernel import (
    RULES_KERNEL_ADDENDUM,
    check_kernel_output,
)
from aegis_ai.features.data_models import feature_deps
from aegis_ai.kernel_classifier import is_kernel_component
from aegis_ai.prompt import AegisPrompt
from aegis_ai.toolsets.tools.cwe import cwe_manager

logger = logging.getLogger(__name__)


def _build_cve_input(
    cve_id: CVEID,
    static_context: Any = None,
    exclude_fields: list[str] | None = None,
) -> CVEFeatureInput:
    """Build CVEFeatureInput from static context or an OSIDB retrieval."""
    if isinstance(static_context, dict):
        desc = (
            static_context.get("comment_zero")
            or static_context.get("cve_description")
            or static_context.get("description")
        )
        inp = CVEFeatureInput(
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
            steering_notes=static_context.get("steering_notes"),
        )
    else:
        inp = CVEFeatureInput(cve_id=cve_id)

    if exclude_fields:
        updates: dict[str, Any] = {}
        for field_name in exclude_fields:
            normalized = field_name.replace("cve_description", "description")
            if normalized == "all_cvss_scores":
                updates["cvss_scores"] = None
            elif normalized == "rh_cvss_score":
                if inp.cvss_scores is not None:
                    updates["cvss_scores"] = [
                        s
                        for s in inp.cvss_scores
                        if not (isinstance(s, dict) and s.get("issuer") == "RH")
                    ]
            elif normalized in CVEFeatureInput.model_fields:
                updates[normalized] = None
        if updates:
            inp = inp.model_copy(update=updates)

    return inp


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
        """Reconcile suggested CVSS score with the parsed vector score."""
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
                - Use `steering_notes` only as internal guidance. Do not quote or paraphrase it in the explanation.
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
    def reconcile_severity(output, call_str) -> str:
        """LLM self-consistency check.

        If the LLM's stated impact matches its CVSS band, keep it.
        If they disagree, trust the CVSS band (quantitative >
        qualitative).

        Returns a trace string explaining the decision.
        """
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
                f"llm_cvss={llm_cvss:.1f}; "
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
            f"llm_cvss={llm_cvss:.1f}; "
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
    def post_process(output, call_str):
        """Run CVSS post-processing and kernel-impact adjustments on the result."""
        SuggestImpact.post_process_cvss(output, call_str)
        pre_reconcile_impact = output.impact
        trace = SuggestImpact.reconcile_severity(output, call_str)

        if output.impact != pre_reconcile_impact:
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

    async def _revise_explanation(
        self,
        result,
        original_score,
        original_impact,
        original_vector,
        trace,
        call_str,
        *,
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
            steering_notes = cve_context.get("steering_notes")
            parts: list[str] = []
            if title:
                parts.append(f"Title: {title}")
            if components:
                parts.append(f"Components: {', '.join(components)}")
            if description_text:
                parts.append(f"Description: {description_text}")
            if steering_notes is not None:
                parts.append(
                    f"Internal analyst steering_notes (data): {steering_notes!r}"
                )
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
            "level of detail.  Use steering_notes only as internal guidance; "
            "do not quote or paraphrase them in the explanation, including "
            "content copied or paraphrased in the original explanation. "
            "Return only the revised explanation text."
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
            revision_prompt = AegisPrompt(
                user_instruction=(
                    f"Original explanation:\n{result.output.explanation}\n\n{follow_up}"
                ),
                goals="",
                rules="",
                context=CVEFeatureInput(cve_id=result.output.cve_id),
            )
            async with llm_sem:
                if not await revision_prompt.is_safe():
                    raise RuntimeError("Safety agent blocked the revision prompt")
                revision = await asyncio.wait_for(
                    self._run(
                        call_str,
                        revision_prompt,
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

    async def exec(
        self,
        cve_id: CVEID,
        static_context: Any = None,
        *,
        extra_exclude_osidb_fields: list[str] | None = None,
        disabled_tools: set[str] | None = None,
    ):
        """Suggest overall impact, CVSS vector, and related fields for a CVE."""
        use_kernel_classifier = get_settings().use_kernel_classifier

        use_static = (
            static_context
            and isinstance(static_context, dict)
            and static_context.get("cvss_scores") is not None
        )
        resolved_static_context = static_context if use_static else None
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

        exclude = [
            "affects",
            "impact",
            "mitigation",
            "rh_cvss_score",
            "statement",
        ]
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
            static_context=resolved_static_context if use_static else None,
            is_kernel_cve=is_kernel,
            classifier_attempted=use_kernel_classifier and is_kernel,
            extra_exclude_osidb_fields=extra_exclude_osidb_fields or [],
            disabled_tools=disabled_tools or set(),
        )
        if pre_clf is not None:
            deps.classifier_result = pre_clf

        output_schema = SuggestImpactModel.model_json_schema()
        if not is_kernel:
            output_schema.get("properties", {}).pop(
                "classifier_disagreement_rationale", None
            )

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
            rules=self._RULES_BASE + RULES_KERNEL_ADDENDUM
            if is_kernel
            else self._RULES_BASE,
            context=_build_cve_input(cve_id, static_context, exclude),
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

        trace = SuggestImpact.post_process(result.output, call_str)

        vector_changed = result.output.cvss3_vector != original_vector
        if vector_changed:
            result.output._explanation_revised = await self._revise_explanation(
                result,
                original_score,
                original_impact,
                original_vector,
                trace,
                call_str,
                cve_context=static_context
                if isinstance(static_context, dict)
                else None,
            )

        result.output._classifier_diagnostics = classifier_result
        result.output._reconciliation_trace = trace

        # Map classifier feature flags to OSIDB label names so the bot
        # can create FlawLabel records (e.g. "kpanic") after saving the flaw.
        if classifier_result and isinstance(classifier_result, dict):
            active = classifier_result.get("active_features", [])
            result.output._flags = sorted(
                {_FLAG_TO_LABEL[f] for f in active if f in _FLAG_TO_LABEL}
            )
        elif is_kernel:
            # without classifier map `A:H` in CVSS to `kpanic` for kernel CVEs
            cvss3_vector = result.output.cvss3_vector
            if cvss3_vector and "A:H" in cvss3_vector:
                result.output._flags = ["kpanic"]

        return result


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        """Suggest CWE identifiers for a CVE from available flaw context."""
        exclude = ["cwe_id"]
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
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
            context=_build_cve_input(cve_id, static_context, exclude),
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
        exclude: list[str] = []
        deps = feature_deps(cve_id=str(cve_id), exclude_osidb_fields=exclude)
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
            context=_build_cve_input(cve_id, static_context, exclude),
            output_schema=PIIReportModel.model_json_schema(),
        )
        return await self.guarded_run(prompt, deps=deps, output_type=PIIReportModel)


class SuggestDescriptionText(Feature):
    """Based on current CVE information and context suggest a description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        exclude = ["title", "cve_description"]
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
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
                - Use `steering_notes` only as internal guidance. Do not quote or paraphrase it in the title or description.
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
            context=_build_cve_input(cve_id, static_context, exclude),
            output_schema=SuggestDescriptionModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestDescriptionModel
        )


class SuggestStatementText(Feature):
    """Based on current CVE information and context suggest a statement and mitigation."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        exclude = ["statement", "mitigation"]
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
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
            - Use `steering_notes` only as internal guidance. Do not quote or paraphrase it in the statement or mitigation.
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
            context=_build_cve_input(cve_id, static_context, exclude),
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
        exclude = ["affects", "components"]
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
            static_context=static_context if use_static else None,
        )
        prompt = AegisPrompt(
            user_instruction="From the provided CVE data (title, description, statement, references, affects, comments, etc.), identify the affected software component(s). "
            "Use the OSIDB tool to retrieve flaw data when cve_id is provided; when full context is already provided, the tool returns that data. Leverage all available fields to infer components.",
            # Prompt ambiguity (AEGIS-496): no rule below says advisory-listed
            # versioned Go module paths (e.g. podman /v4+/v5, no distro name, no
            # unsuffixed path) replace the project/distro name, and the OAuth2
            # Proxy rule (distro name, never forced /vN) pulls the other way —
            # models intermittently answer 'podman' instead of the listed paths.
            goals="""
                - Only list components that are *directly vulnerable* — the upstream artifact where the bug exists and the fix is applied. Do not list libraries, runtimes, or standard library modules that the CVE description merely *mentions*, *uses*, or *references* as execution context. Each component you list must be one where an upstream patch or release directly addresses the flaw.
                - From all available CVE/OSIDB data (title, comment_zero, description, statement, mitigation, comments, references, affects, cvss_scores, cwe_id, impact), identify the affected software component(s).
                - List component names (package names) in the output 'components' field.
                - OSIDB component naming is the source of ground truth. Infer the affected components using that naming convention; upstream advisory names and Go module declarations are supporting evidence, not a reason to replace OSIDB names with different identifiers.
                - Where a Package URL (PURL) is identified use the name part of the PURL, without any namespace or type prefix. Exception: for Maven packages, always include the groupId and use groupId/artifactId format with a forward slash separator (e.g. 'com.mchange/mchange-commons-java' not 'mchange-commons-java', 'org.traccar/traccar' not 'org.traccar:traccar', 'org.apache.sshd/sshd-core' not just 'sshd-core'). Similarly, for PHP Composer packages, always include the vendor and use vendor/package format (e.g. 'phpseclib/phpseclib' not 'phpseclib').
                - Never prefix component names with ecosystem identifiers: no 'python-', 'nodejs-', or 'rubygem-' prefixes. Use the bare package name (e.g. 'cryptography' not 'python-cryptography', 'dotenv' not 'python-dotenv', 'axios' not 'nodejs-axios', 'rack' not 'rubygem-rack'). Strip the prefix even when the upstream project name includes it (e.g. PyPI package 'python-dotenv' → 'dotenv'). Only strip the exact prefixes listed above — 'node-' is NOT an ecosystem prefix (e.g. npm package 'node-forge' → 'node-forge', not 'forge'). Exception: keep the 'rust-' prefix — it is a Red Hat distro naming convention, not an ecosystem prefix (e.g. 'rust-openssl', 'rust-coreutils').
                - For Go packages outside stdlib, use the full affected module or package paths recorded by OSIDB. Preserve major-version segments when they are part of those component names (e.g. 'github.com/containerd/containerd/v2', 'github.com/go-acme/lego/v4') and affected package specificity (e.g. 'golang.org/x/net/html', 'golang.org/x/oauth2/jws'). OSIDB may instead use an unsuffixed repository path or also record a distribution package name: OAuth2 Proxy is represented by 'oauth2-proxy' and 'github.com/oauth2-proxy/oauth2-proxy', not a forced '/v7' path. Do not add or strip version segments solely to conform to upstream semantic import versioning.
                - Go modules follow Semantic Import Versioning: the repository path without a suffix is the module path for major versions 0 and 1, and every major version 2 or higher is a distinct module path with /v2, /v3, ... appended. When the affected version range spans multiple major versions, list the module path for every affected major version: a grpc-gateway flaw affecting versions 'up to v2.28.0' spans the v1 and v2 series, so the components are 'github.com/grpc-ecosystem/grpc-gateway' and 'github.com/grpc-ecosystem/grpc-gateway/v2'. Exclude a major version only when the evidence shows it is unaffected: the MongoDB Go Driver Client.BulkWrite flaw affects only 'go.mongodb.org/mongo-driver/v2' because the vulnerable API does not exist in the unsuffixed v1 module.
                - If the component is from the Python standard library, use 'python' as the component name.
                - If the vulnerability is *in* the Go standard library itself (i.e., the upstream fix is a patch to the Go source tree, such as a Go release note listing the CVE), keep the full stdlib path (e.g. 'crypto/internal/nistec', 'crypto/x509', 'cmd/go', 'net/http/internal') and return it first in the components array in addition to the component 'golang'. Do NOT add 'golang' or Go stdlib paths when the vulnerability is in a third-party Go module that merely *calls* stdlib functions — only the third-party module itself is vulnerable. For example, a bug in rclone that involves net/http handling does NOT make 'net/http' or 'golang' a vulnerable component.
                - Use Red Hat distribution package names, not upstream project or product names. Examples: Linux kernel → 'kernel', Google Chrome/Chromium (including sub-components like V8, Blink, ANGLE, PDFium, Skia, DevTools, WebGL, WebML, Compositing) → 'chromium-browser', MySQL Server → 'mysql', uutils/coreutils → 'rust-coreutils', OpenSSL Rust bindings → 'rust-openssl', Mbed TLS → 'mbedtls', PowerDNS Recursor → 'pdns-recursor', Roundcube Webmail → 'roundcubemail', OpenPrinting CUPS → 'cups', .NET Framework → 'dotnet', GLib/GLib2 → 'glib', `XML::Parser` → 'perl-xml-parser'. For Go packages, follow the OSIDB module/package naming rule above, including distribution package names when OSIDB records them alongside module paths.
                - For the Qt framework, use the Red Hat umbrella component names 'qt', 'qt5', or 'qt6' — not individual sub-module packages (e.g. 'qt6-qtbase', 'qt5-qtconnectivity'). If the CVE affects Qt5, use 'qt5'; if Qt6, use 'qt6'; if Qt in general or both, use 'qt' (or include all applicable: 'qt', 'qt5', 'qt6').
                - Use the source component name, not binary or subpackage names. Examples: Redis → 'redis' not 'redis-server', Apache HTTP Server → 'httpd' not 'httpd-core'.
                - When the CVE title or GitHub repository name differs from the actual package name in the ecosystem registry (npm, PyPI, crates.io, etc.), always use the registry name (e.g. GitHub repo 'node-tar' is published to npm as 'tar' → use 'tar'; GitHub repo 'forge' is published to npm as 'node-forge' → use 'node-forge'; GitHub repo 'tar-rs' is published to crates.io as 'tar' → use 'tar').
                - For proprietary OS kernel vulnerabilities (macOS, iOS, Windows, etc.), use the OS name as the component (e.g. 'macOS', 'iOS', 'Windows'), not 'kernel'. Only use 'kernel' for the Linux kernel.
                - When a vulnerability is in a product's own code (e.g. its shared certificate validation logic), list only the product itself as the affected component. Do not list services, protocols, or features that the product merely uses or integrates (e.g. RouterOS using OpenVPN/CAPsMAN/Dot1x → 'RouterOS' only).
                - Similarly, a vulnerability in a specific application or library does not make its language runtime or standard library a separate vulnerable component. Do not add language/runtime names (e.g., 'golang', 'python', 'java') or standard library module paths as components unless the vulnerability is *in* the language/runtime itself.
                - Use the bare package/project name, not a descriptive label from the CVE title. Examples: 'musl' not 'musl libc', 'glibc' not 'GNU C Library', 'openssl' not 'OpenSSL library'. This rule is about dropping informal suffixes like 'libc' or 'library' — it does NOT override the ecosystem prefix-stripping rules above (e.g. 'python-dotenv' → 'dotenv' still applies).
                - Never extract product edition abbreviations or suffixes as standalone component names. Tokens like 'CE' (Community Edition), 'EE' (Enterprise Edition), 'SE' (Standard Edition), 'Plus', 'Pro', etc. are product edition qualifiers, not component names. When a product includes an edition suffix (e.g. 'pfSense CE', 'pfSense Plus and CE', 'GitLab EE'), extract only the base product name (e.g. 'pfSense', 'GitLab').
                - Determine which package ecosystem(s) are impacted by the vulnerability. Many components are published to multiple ecosystems (e.g. Redis has pypi, npm, generic); the vulnerability may only affect one. Populate the 'ecosystems' field with one or more of: cargo, composer, conan, cran, gem, generic, golang, hex, luarocks, maven, npm, nuget, opam, otp, pub, pypi, swift, unknown.
                - Provide a concise explanation of the rationale.
            """,
            rules="""
                - Use the osidb_tool with the provided cve_id to retrieve CVE flaw data.
                - Leverage title, description (or comment_zero), statement, references, affects, comments, and any other fields to infer affected components.
                - Use github mcp tool to resolve vulnerability reference URLs if present (e.g. to confirm repo/component names, inspect commit diffs to identify which specific submodules or artifacts are affected).
                - When a CVE mentions an umbrella project (e.g. 'Spring Framework', 'Apache Commons'), do not return the umbrella name — use tools to identify the specific affected Maven artifacts or submodules (e.g. 'org.springframework/spring-webmvc' not 'Spring Framework').
                - If GHSA reference URLs are present in the flaw data, pass them to the osv_dev_ghsa tool to get structured affected-package data (package names, ecosystems, PURLs, version ranges) for component identification.
                - Use osv_dev_ghsa_tool responses to determine impacted ecosystems — the affected[].package.ecosystem field is the most authoritative ecosystem signal.
                - When osv_dev_ghsa_tool returns an affected package name, use it to identify the vulnerable artifact rather than guessing from the CVE title or description. The GHSA package name is a registry identifier; OSIDB remains authoritative for output component naming when the names differ.
                - Analyze CVE reference URLs to determine ecosystem: advisory URLs often indicate it (GHSA advisories, npmjs.com, pypi.org links, commit URLs pointing to upstream source). A vulnerability in core source code does not automatically mean every language binding is affected.
                - Cross-check each candidate component: verify that the upstream fix (patch, commit, release) addresses a bug *in that specific component's code*. If the fix is only in one upstream project, other projects you are considering are likely mentioned for context, not themselves vulnerable. A single affected package in osv_dev_ghsa_tool or github tool data is strong evidence against adding unrelated artifacts, but does not exclude multiple OSIDB component names for that same vulnerable software.
                - Use 'generic' only for software distributed outside any language package registry — typically via tarballs, zip archives, container images, or OS packages. Examples: Apache Tomcat, Apache HTTP Server (httpd), Nginx, PostgreSQL, MariaDB, Samba, BIND. If the component is published to a package registry (npm, PyPI, Maven Central, crates.io, RubyGems, hex.pm, etc.), use that registry's ecosystem even if the component is an application or CLI rather than a library.
                - 'Written in language X' does NOT imply ecosystem X. The ecosystem should reflect the *distribution channel*, not the implementation language. A Java application distributed as a tarball (e.g. Apache Tomcat) is 'generic', not 'maven'. But a Java library published to Maven Central is 'maven', and a CLI tool installed via `npm install -g` is 'npm'.
                - When no tool data (OSV.dev, GHSA) provides an explicit ecosystem for software distributed outside a package registry, prefer 'generic' over a language ecosystem inferred only from implementation language.
                - When a GitHub security advisory or the CNA package URL reports an ecosystem, use that value mapped onto the allowlist (e.g. 'OTP' → 'otp', 'Hex' → 'hex'). Do not replace it with 'hex' merely because the text mentions hex.pm or Mix. If those sources are absent, an OSV/GHSA ecosystem of 'Hex' maps to 'hex', and packages published on or fetched from the Hex registry use 'hex'. A Mix dependency fetched only via git: or path:, with no Hex coordinate and no advisory ecosystem, is not 'hex'. Do not use 'cargo' for Hex packages merely because a Rust crate may share the same name.
                - Use 'unknown' for the ecosystem only when it genuinely cannot be determined from available data.
                - For Go packages outside stdlib, preserve each distinct affected component identity used by OSIDB. This can include versioned module paths, unsuffixed paths, affected package subpaths, and distribution package names for the same vulnerable software. Do not collapse distinct OSIDB component names into one repository name or expand a module root into a package subpath merely because a vulnerable function lives there. Use advisory package names, PURLs, and upstream module declarations as supporting evidence; do not invent a version segment from a release version alone or let upstream naming override OSIDB. Include multiple paths or package names only when supported as affected components, rather than generating aliases speculatively.
                - Output format: components (list of strings), ecosystems (list of strings), explanation (string), confidence (0.00–1.00).
            """,
            context=_build_cve_input(cve_id, static_context, exclude),
            output_schema=SuggestAffectedComponentsModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestAffectedComponentsModel
        )


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        exclude: list[str] = []
        deps = feature_deps(cve_id=str(cve_id), exclude_osidb_fields=exclude)
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
            context=_build_cve_input(cve_id, static_context, exclude),
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
        exclude: list[str] = []
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
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
- Use `steering_notes` only as internal guidance. Do not quote or paraphrase it in `suggested_statement` or `suggested_mitigation`.
- For all rubric scores and justifications, strengths, critical gaps, value_add, and Customer Lens assessments, use only existing customer-visible flaw content as evidence, including publicly accessible references. Do not treat `steering_notes`, other non-public data, or proposed rewrites as existing customer-visible content.
- If information appears only in `steering_notes` or other non-public data, treat it as missing from the customer-visible content. Score the relevant criteria accordingly and identify what remains unclear or needs manual context; do not assume customers can see or infer it.
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
            context=_build_cve_input(cve_id, static_context, exclude),
            output_schema=QualityReviewModel.model_json_schema(),
        )

        return await self.guarded_run(prompt, deps=deps, output_type=QualityReviewModel)


class SuggestAffectedPackages(Feature):
    """LLM-driven suggestion of source RPM package affectedness."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        # Track tools invoked outside the LLM tool-call loop so they
        # appear in ``tools_used`` even though pydantic-ai won't see them.
        """Suggest which packaged NVRs are affected by a CVE."""
        pre_invoked_tools: list[str] = []

        # Resolve affects data for pre-computation of binary RPMs.
        if isinstance(static_context, dict) and isinstance(
            static_context.get("affects"), list
        ):
            affects = static_context["affects"]
        elif self.agent.name == "RHFeatureAgent":
            cve_data = await osidb_tool.cve_retrieve(cve_id)
            affects = cve_data.affects
            retrieved_context = cve_data.model_dump()
            if isinstance(static_context, dict) and "steering_notes" in static_context:
                retrieved_context["steering_notes"] = static_context["steering_notes"]
            static_context = retrieved_context
            pre_invoked_tools.append("osidb_tool")
        else:
            affects = []

        # Pre-compute binary RPMs (deduplicated by unique package+stream)
        # so the LLM reads them from context instead of making per-affect
        # tool calls that would time out on CVEs with many streams.
        if get_settings().use_build_system_tool and affects:
            if await self._enrich_affects_with_binary_rpms(affects):
                pre_invoked_tools.append("list_binary_rpms")
            if isinstance(static_context, dict):
                static_context["affects"] = affects

        # Only use static_context for deps when it contains affects data;
        # otherwise let the OSIDB tool fetch the full flaw record.
        deps_context = (
            static_context
            if isinstance(static_context, dict)
            and isinstance(static_context.get("affects"), list)
            else None
        )
        exclude: list[str] = []
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=exclude,
            static_context=deps_context,
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
- For affected packages with binary RPM data, produce per-binary affectedness assessments in affected_binaries, with optional subcomponent_hint for sub-binary granularity (e.g., a specific kernel module, an HTTP handler within a library).
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
- Use github MCP tool to inspect commit diffs or repository structure when reference URLs are available.
- Each affect entry may include a binary_rpms field listing the binary RPM subpackages produced by that source package in the given stream. If binary_rpms is not present for an affect and you need this information, you may call list_binary_rpms_tool with the package name and ps_update_stream. If an affect entry has binary_rpms_not_found set to true, no build was found for that package/stream combination — do not call list_binary_rpms_tool for it again.
- When binary RPM names are available (from binary_rpms or list_binary_rpms_tool), populate affected_binaries with one BinaryAffectednessEntry per binary RPM. For each binary, set affected to whether the vulnerability impacts that specific binary, and provide a concise one-sentence explanation.
- Use subcomponent_hint on a BinaryAffectednessEntry when the affected component is more specific than the binary itself (e.g., 'XFS kernel module', 'HTTP/2 handler'). Do not use it to list individual source files.
- When binary RPM data is not available, leave affected_binaries empty. The package-level explanation should still describe which sub-components are affected when known.
- The affected field in each AffectedPackageEntry reflects YOUR analysis of whether the package is affected by the vulnerability, considering the technical context.
- Set confidence based on how much technical evidence is available to support your determination.
- Output format: affected_packages (list of AffectedPackageEntry), explanation (string), data_quality, confidence.
""",
            context=_build_cve_input(cve_id, static_context, exclude),
            output_schema=SuggestAffectedPackagesModel.model_json_schema(),
        )

        from aegis_ai.toolsets import build_system_toolset

        result = await self.guarded_run(
            prompt,
            deps=deps,
            output_type=SuggestAffectedPackagesModel,
            toolsets=[build_system_toolset],
        )

        for tool_name in pre_invoked_tools:
            if tool_name not in result.output.tools_used:
                result.output.tools_used.append(tool_name)

        if isinstance(static_context, dict) and isinstance(
            static_context.get("affects"), list
        ):
            self._reattach_build_nvr(result.output, static_context["affects"])

        return result

    @staticmethod
    def _reattach_build_nvr(
        output: SuggestAffectedPackagesModel, affects: list
    ) -> None:
        """Stamp build_nvr deterministically from enriched affects data.

        The LLM may omit or alter build_nvr, so we overwrite it from the
        authoritative enrichment data keyed by (purl, ps_update_stream).
        """
        nvr_map: dict[tuple[str, str], str] = {}
        for a in affects:
            if not isinstance(a, dict):
                continue
            purl = a.get("purl")
            stream = a.get("ps_update_stream")
            nvr = a.get("build_nvr")
            if purl and stream and nvr:
                nvr_map[(purl, stream)] = nvr

        for pkg in output.affected_packages:
            key = (pkg.purl, pkg.ps_update_stream)
            nvr = nvr_map.get(key)
            if nvr is not None:
                pkg.build_nvr = nvr

    @staticmethod
    async def _enrich_affects_with_binary_rpms(affects: list) -> bool:
        """Pre-compute binary RPMs for unique (package, stream) pairs.

        Successful lookups inject a ``binary_rpms`` list into the affect
        dict.  Completed ``not_found`` lookups set ``binary_rpms_not_found``
        to ``True`` so the LLM prompt skips them.  Retryable errors leave
        no marker, keeping the tool-call path open.

        Returns True if at least one lookup was attempted.
        """
        from collections import defaultdict

        from packageurl import PackageURL

        from aegis_ai.toolsets.tools.build_system import (
            ENRICHMENT_TIMEOUT_SECS,
            _lookup_binary_rpms_batch,
        )

        pkg_streams: dict[str, list[str]] = defaultdict(list)
        for a in affects:
            if not isinstance(a, dict):
                continue
            purl_str = a.get("purl")
            stream = a.get("ps_update_stream")
            if purl_str and stream:
                try:
                    pkg_name = PackageURL.from_string(purl_str).name
                except ValueError:
                    continue
                if stream not in pkg_streams[pkg_name]:
                    pkg_streams[pkg_name].append(stream)

        if not pkg_streams:
            return False

        total_pairs = sum(len(s) for s in pkg_streams.values())
        logger.info(
            "[list_binary_rpms] looking up %d unique (package, stream) pairs "
            "(%d packages) from %d affects",
            total_pairs,
            len(pkg_streams),
            len(affects),
        )

        _NOT_FOUND: list[str] = []

        _LookupResult = tuple[list[str] | None, str | None]

        deadline = time.monotonic() + ENRICHMENT_TIMEOUT_SECS

        async def _lookup_package(
            pkg: str, streams: list[str]
        ) -> list[tuple[tuple[str, str], _LookupResult]]:
            """Batch-resolve all streams for one package."""
            try:
                batch = await asyncio.to_thread(
                    _lookup_binary_rpms_batch, pkg, streams, deadline=deadline
                )
            except Exception:
                logger.exception("[list_binary_rpms] %s unexpected error", pkg)
                return [((pkg, s), (None, None)) for s in streams]

            mapped: list[tuple[tuple[str, str], _LookupResult]] = []
            for result in batch:
                key = (result.package, result.ps_update_stream)
                if result.status == "success":
                    logger.info(
                        "[list_binary_rpms] %s/%s -> %d binary RPMs",
                        result.package,
                        result.ps_update_stream,
                        len(result.binary_rpms),
                    )
                    mapped.append((key, (result.binary_rpms, result.build_nvr)))
                elif result.status == "not_found":
                    mapped.append((key, (_NOT_FOUND, None)))
                else:
                    logger.warning(
                        "[list_binary_rpms] %s/%s failed: %s",
                        result.package,
                        result.ps_update_stream,
                        result.error_message,
                    )
                    mapped.append((key, (None, None)))
            return mapped

        batch_results = await asyncio.gather(
            *[_lookup_package(pkg, streams) for pkg, streams in pkg_streams.items()]
        )

        rpm_cache: dict[tuple[str, str], _LookupResult] = {
            k: lr for batch in batch_results for k, lr in batch
        }

        _ENRICHMENT_KEYS = ("binary_rpms", "binary_rpms_not_found", "build_nvr")

        enriched = 0
        for a in affects:
            if not isinstance(a, dict):
                continue
            purl_str = a.get("purl")
            stream = a.get("ps_update_stream")
            if not purl_str or not stream:
                continue
            try:
                pkg_name = PackageURL.from_string(purl_str).name
            except ValueError:
                continue
            key = (pkg_name, stream)
            rpms, build_nvr = rpm_cache.get(key, (None, None))
            if rpms is None:
                continue
            for ek in _ENRICHMENT_KEYS:
                a.pop(ek, None)
            if rpms is _NOT_FOUND:
                a["binary_rpms_not_found"] = True
            else:
                a["binary_rpms"] = rpms
                if build_nvr:
                    a["build_nvr"] = build_nvr
            enriched += 1

        logger.info("[list_binary_rpms] enriched %d/%d affects", enriched, len(affects))
        return bool(pkg_streams)


class QueryAffectedComponents(DeterministicFeature):
    """Deterministic query: return affected components from OSIDB affects data."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        """Query already-known affected components for a CVE."""
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


_DOWNSTREAM_DISCLAIMER = "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert."
_FLAW_BODY_KEYS = (
    "components",
    "title",
    "comment_zero",
    "description",
    "cve_description",
)


class SuggestManifestComponentAndState(Feature):
    """Map flaw components to same-project downstream names with affectedness.

    Prefetches wide bomq/Anitya catalog candidates, then asks the agent to
    refine keep/drop, version range, and affectedness after a required
    vulnerable-code usage step. Names invent outside the candidate set are
    post-filtered out. Soft-label packaging drop reasons (plugins, lookalikes,
    subpackages, …) and version_package / compat keeps are hard-enforced after
    the agent, not only advisory.
    """

    def __init__(self, agent):
        super().__init__(agent)
        self._downstream_candidates = None

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        """Prefetch catalog candidates, run the agent when needed, and post-filter mapped names."""
        pre_invoked_tools: list[str] = ["osidb_tool"]
        flaw = await _downstream_flaw(cve_id, static_context)
        gathered = await asyncio.to_thread(collect_downstream_candidates, flaw)
        self._downstream_candidates = gathered
        pre_invoked_tools.extend(gathered.tools_used)

        if not gathered.seeds or is_kernel_component(gathered.seeds):
            output = SuggestManifestComponentAndStateModel(
                cve_id=cve_id,
                manifest_components=[],
                usage=_default_manifest_usage(gathered.seeds),
                explanation=gathered.explanation,
                confidence=0.9,
                data_quality=_downstream_data_quality(flaw),
                tools_used=list(dict.fromkeys(pre_invoked_tools)),
                disclaimer=_DOWNSTREAM_DISCLAIMER,
            )
            logger.info(
                "SuggestManifestComponentAndState(%s) = %s",
                cve_id,
                output.printable_outcome(),
            )
            return DeterministicResult(output)

        # Catalog outage: empty candidates are untrustworthy. Confidence 0 and
        # _catalog_outage keep suggest_manifest_components from overwriting
        # saved rows or recording a low-confidence skip.
        if gathered.catalog_unavailable:
            output = SuggestManifestComponentAndStateModel(
                cve_id=cve_id,
                manifest_components=[],
                usage=_default_manifest_usage(gathered.seeds),
                explanation=gathered.explanation,
                confidence=0.0,
                data_quality=_downstream_data_quality(flaw),
                tools_used=list(dict.fromkeys(pre_invoked_tools)),
                disclaimer=_DOWNSTREAM_DISCLAIMER,
            )
            output._catalog_outage = True
            logger.warning(
                "SuggestManifestComponentAndState(%s) catalog unavailable: %s",
                cve_id,
                gathered.explanation,
            )
            return DeterministicResult(output)

        if not gathered.candidates:
            output = SuggestManifestComponentAndStateModel(
                cve_id=cve_id,
                manifest_components=[],
                usage=_default_manifest_usage(gathered.seeds),
                explanation=gathered.explanation,
                confidence=0.7,
                data_quality=_downstream_data_quality(flaw),
                tools_used=list(dict.fromkeys(pre_invoked_tools)),
                disclaimer=_DOWNSTREAM_DISCLAIMER,
            )
            logger.info(
                "SuggestManifestComponentAndState(%s) = %s",
                cve_id,
                output.printable_outcome(),
            )
            return DeterministicResult(output)

        baseline = resolve_soft_label_rows(
            gathered.candidates,
            gathered.versions,
            gathered.rhcos_versions,
            gathered.seeds,
            flaw=flaw,
        )
        # Affects are produced from this feature's output (via ACE), not inputs.
        # Large affect tables also blow past model context limits (AEGIS-540).
        deps = feature_deps(
            cve_id=str(cve_id),
            exclude_osidb_fields=["affects"],
            static_context=flaw if isinstance(flaw, dict) else None,
        )
        prompt = AegisPrompt(
            user_instruction=(
                "Map the flaw's upstream component seeds to same-project "
                "downstream packaging names and suggest affectedness. First "
                "decide which catalog hits run the vulnerable code. Use the "
                "prefetched catalog candidates as the primary allowed name set."
            ),
            goals="""\
- Required usage step before keep/drop: from the flaw text and reference URLs, name the vulnerable unit (the patched package or submodule, not a parent import that only shares a module path) and the caller role (every_importer when every API importer is in scope; product_feature when only a named product feature runs the bug).
- Put catalog names that run that code in usage.runs_vulnerable_code (downstream rebuilds and server packaging that exercise the bug, such as github.com/openshift-priv/prometheus, prometheus, and prometheus3.13). Put names that only link a shared parent module in usage.importer_only (metrics importers, client libraries). Same-project rebuilds and version packages are not importers. The patched submodule stays in usage.vulnerable_unit; when caller_role is product_feature it is not required as a final row.
- Keep same-project packaging names that appear in the prefetched candidates and that survive the usage step.
- Keep packaging-prefix rebuilds (mingw- / cross-) and compat-* rebuilds. Drop digit-prefixed product rebuilds (jbcs-httpd24-openssl) and sysroot-*-<seed> subpackages.
- Keep OpenShift Go fork paths: github.com/openshift-priv/<project> is looked up as github.com/openshift/<project> (public fork of the upstream repo with the same name). Treat that packaging as same-project downstream of the upstream seed — not a separate upstream.
- Keep every catalog-present version-suffixed packaging name for the seed (libsoup3, openssl3, zabbix6.0, OpenImageIO2.5); do not drop them as separate upstreams.
- Attach exactly one of build_type, ecosystem, or rhcos per row. Keep the soft-label baseline search key for each kept name: build_type for exact build-name matches (rpm/container/maven/generic builds); ecosystem for bundled registry packages (maven GAVs, npm, golang modules, …). Never emit ecosystem: rpm. Never rewrite ecosystem:maven to build_type:maven for a coordinate that only appears as a bundled maven component.
- Add an rhcos: rpm companion when RHCOS version samples exist for a kept RPM name.
- Infer the advisory version range from upstream_data when present, otherwise from CVE/advisory text.
- Suggest affectedness AFFECTED / NOTAFFECTED / UNKNOWN / null (compat blank) from sampled versions: SRPM upstream versions for RPM rows, and nested bomq component versions for ecosystem rows (golang, maven, npm, …). Any overlapping sample is AFFECTED; every sample outside the range is NOTAFFECTED. Importer-only names kept for a small build count should be NOTAFFECTED.
- Explain keep/drop, usage, and verdicts briefly, including why high-build-count importers were omitted or small importers were kept as NOTAFFECTED.
""",
            rules="""\
- Never invent a name that is absent from the candidates list (except rhcos companions for an already-kept RPM name, or a server/submodule name confirmed with bomq_components_tool).
- Soft-label baseline rows are a starting point; refine with tools when identity or range is unclear.
- When a full Go, Maven, or scoped-npm path is kept, do not also emit its bare ecosystem shorthand (e.g. keep github.com/rclone/rclone, not ecosystem rclone). Keep build-typed packaging that shares the final token (prometheus RPM beside github.com/openshift-priv/prometheus).
- When caller_role is product_feature, do not put a high build_count parent module that only importers link into runs_vulnerable_code; prefer the openshift-priv or upstream application rebuild and the server RPM builds.
- When caller_role is every_importer, high build_count on the vulnerable unit itself is expected and must stay.
- compat-<seed><digits> rows stay with blank (null) affectedness for manual review.
- Drop subpackages (including sysroot-*-<seed>), digit-prefixed product rebuilds, language bindings, engines/plugins, and unrelated lookalikes.
- Do not treat github.com/openshift-priv/<project> as a different upstream; map it to github.com/openshift/<project> and keep it when <project> matches the seed or a reference caller GitHub repo name.
- Web search and Anitya are for ambiguous rebuild / soname-glue / rename identity — not for rejecting catalog version-suffixed names.
- Compare sampled upstream VERSION (epoch/release stripped; Go leading v stripped), never product STREAM names.
- Use bomq_components_tool, bomq_build_versions_tool, or anitya_projects_tool when the prefetch is insufficient.
- Output SuggestManifestComponentAndStateModel: cve_id, manifest_components, usage, explanation, confidence, data_quality.
""",
            context=DownstreamFeatureContext(
                cve_id=cve_id,
                flaw_components=gathered.seeds,
                advisory_text=gathered.advisory_text,
                upstream_data=flaw.get("upstream_data")
                if isinstance(flaw, dict)
                else None,
                downstream_candidates=gathered.to_prompt_dict(),
                soft_label_baseline=[
                    {
                        "name": row.name,
                        "build_type": row.build_type,
                        "ecosystem": row.ecosystem,
                        "rhcos": row.rhcos,
                        "affectedness": row.affectedness,
                        "evidence": row.evidence,
                    }
                    for row in baseline
                ],
            ),
            output_schema=SuggestManifestComponentAndStateModel.model_json_schema(),
        )

        from aegis_ai.toolsets import downstream_toolset

        result = await self.guarded_run(
            prompt,
            deps=deps,
            output_type=SuggestManifestComponentAndStateModel,
            toolsets=[downstream_toolset],
        )

        output = result.output
        output.cve_id = cve_id
        short_names = suppressed_short_path_names(
            gathered.seeds, gathered.allowed_names()
        )
        rejected = rejected_soft_label_names(gathered.candidates)
        allowed = gathered.allowed_names() - short_names - rejected
        output.manifest_components = post_filter_manifest_entries(
            output.manifest_components,
            allowed,
        )
        # Blocking BOMQ confirms must not run on the event loop.
        output.manifest_components, output.explanation = await asyncio.to_thread(
            apply_usage_policy,
            output.manifest_components,
            vulnerable_unit=output.usage.vulnerable_unit,
            caller_role=output.usage.caller_role,
            runs_vulnerable_code=output.usage.runs_vulnerable_code,
            importer_only=output.usage.importer_only,
            candidates=gathered.candidates,
            explanation=output.explanation or gathered.explanation,
            confirm_name=_confirm_catalog_name,
        )
        # Align after usage policy so re-added rows pick up baseline verdicts.
        output.manifest_components = align_manifest_search_keys(
            output.manifest_components,
            baseline,
        )
        output.manifest_components = ensure_soft_label_keeps(
            output.manifest_components,
            baseline,
            gathered.candidates,
        )
        output.manifest_components = drop_soft_label_rejects(
            output.manifest_components,
            gathered.candidates,
        )
        promoted, promotion_note = await asyncio.to_thread(
            promote_reference_caller_modules,
            output.manifest_components,
            flaw if isinstance(flaw, dict) else {},
            gathered.seeds,
            _confirm_catalog_name,
        )
        output.manifest_components = drop_short_segments_of_kept_modules(promoted)
        if promotion_note and promotion_note not in (output.explanation or ""):
            output.explanation = (
                f"{output.explanation.rstrip()} {promotion_note}".strip()
                if output.explanation
                else promotion_note
            )
        output.manifest_components = drop_suppressed_short_path_entries(
            output.manifest_components,
            short_names,
        )
        output.disclaimer = _DOWNSTREAM_DISCLAIMER
        if not output.explanation:
            output.explanation = gathered.explanation
        for tool_name in pre_invoked_tools:
            if tool_name not in output.tools_used:
                output.tools_used.append(tool_name)

        logger.info(
            "SuggestManifestComponentAndState(%s) = %s",
            cve_id,
            output.printable_outcome(),
        )
        return result

    def _check_output(self, result, deps: Any) -> str | None:
        """Reject outputs with invalid search keys or product_feature importer misuse."""
        output = result.output
        if not isinstance(output, SuggestManifestComponentAndStateModel):
            return None
        for entry in output.manifest_components:
            keys = sum(
                1
                for value in (entry.build_type, entry.ecosystem, entry.rhcos)
                if value is not None
            )
            if keys != 1:
                return (
                    "Each manifest_components entry must set exactly one of "
                    "build_type, ecosystem, or rhcos. Fix the list and try again."
                )
        if not (output.usage.vulnerable_unit or "").strip():
            return (
                "usage.vulnerable_unit must name the patched package or "
                "submodule. Fill usage and try again."
            )
        if output.usage.caller_role != "product_feature":
            return None
        counts = {}
        if self._downstream_candidates is not None:
            counts = self._downstream_candidates.build_counts()
        runs = {
            name.casefold()
            for name in output.usage.runs_vulnerable_code
            if isinstance(name, str)
        }
        offenders = []
        for entry in output.manifest_components:
            folded = entry.name.casefold()
            count = counts.get(folded)
            if (
                count is not None
                and count >= IMPORTER_AFFECT_LIMIT
                and folded not in runs
            ):
                offenders.append(f"{entry.name} ({count} builds)")
        if offenders:
            return (
                "caller_role is product_feature, but these high build_count "
                "manifest names are not in usage.runs_vulnerable_code: "
                f"{', '.join(offenders)}. Move names that run the vulnerable "
                "unit into runs_vulnerable_code, put importer-only parents in "
                "importer_only, and try again."
            )
        return None


def _default_manifest_usage(seeds: list[str]) -> ManifestUsageAnalysis:
    unit = seeds[0] if seeds else "n/a"
    return ManifestUsageAnalysis(
        vulnerable_unit=unit,
        caller_role="every_importer",
        runs_vulnerable_code=[],
        importer_only=[],
    )


def _confirm_catalog_name(name: str):
    """Re-query bomq for an exact component name during usage-policy restore."""
    from aegis_ai.features.cve.downstream import CatalogHit

    rows = query_bomq_components(name, glob=False)
    return [
        CatalogHit(
            row["name"],
            str(row.get("type") or "").casefold(),
            row.get("build_count") if isinstance(row.get("build_count"), int) else None,
        )
        for row in rows
        if isinstance(row.get("name"), str) and isinstance(row.get("type"), str)
    ]


# Fields required for candidate collection and affectedness hints. Present
# keys in static_context (including empty lists) stay as the caller sent them.
_DOWNSTREAM_NEEDED_KEYS = (
    "components",
    "references",
    "upstream_data",
    "comment_zero",
    "description",
    "cve_description",
    "statement",
    "title",
)


def _without_affects(flaw: dict[str, Any]) -> dict[str, Any]:
    """Drop OSIDB affects from a flaw dict used as downstream feature input."""
    if "affects" not in flaw:
        return flaw
    cleaned = dict(flaw)
    cleaned.pop("affects", None)
    return cleaned


async def _downstream_flaw(cve_id: CVEID, static_context: Any) -> dict[str, Any]:
    """Return flaw body for downstream mapping.

    When static context already has the fields needed for candidate collection
    and affectedness hints, use it as-is. Otherwise retrieve the OSIDB flaw and
    fill only missing keys so caller-supplied values stay authoritative.

    Affects are always stripped: they are derived from this feature's output
    and can be large enough to exceed model context limits.
    """
    if isinstance(static_context, dict) and any(
        key in static_context for key in _FLAW_BODY_KEYS
    ):
        missing = [key for key in _DOWNSTREAM_NEEDED_KEYS if key not in static_context]
        if not missing:
            return _without_affects(static_context)
        cve = await osidb_tool.cve_retrieve(cve_id)
        if not hasattr(cve, "model_dump"):
            return _without_affects(static_context)
        fetched = cve.model_dump()
        merged = dict(static_context)
        for key in missing:
            if key in fetched:
                merged[key] = fetched[key]
        return _without_affects(merged)
    cve = await osidb_tool.cve_retrieve(cve_id)
    if hasattr(cve, "model_dump"):
        return _without_affects(cve.model_dump())
    return {"cve_id": str(cve_id)}


def _downstream_data_quality(flaw: dict[str, Any]) -> float:
    """Heuristic data-quality score from flaw components and advisory text."""
    has_components = bool(flaw.get("components"))
    has_text = any(flaw.get(key) for key in _FLAW_BODY_KEYS if key != "components")
    if has_components and has_text:
        return 0.9
    return 0.8
