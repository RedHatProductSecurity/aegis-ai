import asyncio
import io
import json
import logging
import math
import os
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from typing import Sequence, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from google.genai.errors import ServerError
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_evals import Dataset
from pydantic_evals.dataset import EvaluationReport
from pydantic_evals.evaluators import (
    EvaluationReason,
    Evaluator,
    EvaluatorContext,
    LLMJudge,
)
from pydantic_evals.evaluators.common import OutputConfig
from pydantic_evals.reporting import RenderNumberConfig, RenderValueConfig
from pydantic_evals.reporting.render_numbers import default_render_number

from aegis_ai import get_settings
from aegis_ai.agents import agent_default_max_retries
from aegis_ai.features import PROMPT_RETRY_503_DELAY_INIT
from aegis_ai.features.data_models import AegisFeatureModel


# minimal acceptable length of an explanation (where applicable)
EXPLANATION_MIN_LEN = 80

# Centralized rubrics for semantic similarity scoring (used by evals and web service)
# Keys are feature names (e.g., "suggest-title") matching web service feature endpoints
FIELD_RUBRICS = {
    "suggest-title": (
        "Score how much the actual suggested_title field is semantically equivalent "
        "to the expected suggest_title field.  If the key message is the same but the "
        "style is different, the score should not be zero.  If the style is different, "
        "the score should not be 1.0.  Penalize titles that are overly long or that try "
        "to pack every impact dimension into the headline instead of summarizing the core issue."
    ),
    "suggest-description": (
        "Score how much the actual suggested_description field is semantically equivalent "
        "to the expected suggest_description field.  If the key message is the same but "
        "the style is different, the score should not be zero.  If the style is different, "
        "the score should not be 1.0.  Penalize vague or padded prose when the expected text "
        "is precise; reward clear advisory-style wording comparable to a well-written upstream summary."
    ),
    "suggest-statement": (
        "Score semantic equivalence between the actual suggested_statement and the expected "
        "suggested_statement.  Emphasize matching rationale (impact justification in RH context, "
        "preconditions, scope).  The statement should add value beyond restating the CVE "
        "description and should not merely duplicate product/version lists that belong in Affects. "
        "If style differs but the core message overlaps, the score should "
        "be > 0.0 and < 1.0 depending on overlap.  Only assign 0.0 if the actual is irrelevant "
        "to the CVE or contradicts the expected meaning.  When partially aligned but missing details, "
        "prefer a low non-zero score (e.g., 0.12–0.3) rather than 0.0."
    ),
    "suggest-mitigation": (
        "Score how much the actual suggested_mitigation field is semantically equivalent to the "
        "expected suggested_mitigation field.  If the key message is the same but the style is "
        "different, the score should not be zero.  If the style is different, the score should "
        "not be 1.0."
    ),
}

# penalize incorrect suggestions with high confidence rate (the difference
# between the base score and confidence rate is divided by this number and
# subtracted from the base score)
HIGH_CONFIDENCE_PENALTY_DIVISOR = 4.0

# penalize correct suggestions with low confidence rate (the difference
# between the base score and confidence rate is divided by this number and
# subtracted from the base score)
LOW_CONFIDENCE_PENALTY_DIVISOR = 4.0

# minimal acceptable score returned by an evaluator
MIN_SCORE_THRESHOLD = 0.1

# evaluation summary for each evaluated feature
eval_summary: dict[str, str] = {}

# evaluation metrics (dict of ReportCaseAggregate objects)
eval_metrics = {}


logger = logging.getLogger(__name__)


# use the primary LLM also for evals unless overridden by the environment variables
evals_llm_model = get_settings().default_llm_model
evals_llm_settings = get_settings().default_llm_settings
evals_llm_model_name = os.getenv(
    "AEGIS_EVALS_LLM_MODEL", get_settings().default_llm_model_name
)

# if AEGIS_EVALS_LLM_HOST is set, use an independent LLM for evals
evals_llm_host = os.getenv("AEGIS_EVALS_LLM_HOST")
if evals_llm_host == "https://generativelanguage.googleapis.com":
    evals_llm_model = GoogleModel(model_name=evals_llm_model_name)
    evals_llm_settings = GoogleModelSettings(
        google_thinking_config={"include_thoughts": False},
    )
elif evals_llm_host:
    # use an independent LLM for evals
    evals_llm_api_key = os.getenv("AEGIS_EVALS_LLM_API_KEY", "")
    evals_llm_model = OpenAIChatModel(
        model_name=evals_llm_model_name,
        provider=OpenAIProvider(
            base_url=f"{evals_llm_host}/v1/",
            api_key=evals_llm_api_key,
        ),
    )
    evals_llm_settings = OpenAIResponsesModelSettings()


def reflect_confidence(ctx, score):
    """reflect `confidence` ratio in the score"""
    conf_diff = ctx.output.confidence - score
    if 0.0 < conf_diff:
        # penalize incorrect suggestions with high confidence rate
        return score - conf_diff / HIGH_CONFIDENCE_PENALTY_DIVISOR
    else:
        # penalize correct suggestions with low confidence rate
        return score + conf_diff / LOW_CONFIDENCE_PENALTY_DIVISOR


class FeatureMetricsEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx: EvaluatorContext[str, AegisFeatureModel]) -> float:
        # start with confidence metric
        score = ctx.output.confidence

        # do not check explanation length for IdentifyPII and CVSSDiffExplainer because
        # the explanation is empty in the most common case
        if not hasattr(ctx.output, "contains_PII") and not hasattr(
            ctx.output, "nvd_cvss3_score"
        ):
            expl_diff = EXPLANATION_MIN_LEN - len(ctx.output.explanation)  # type: ignore
            if 0 < expl_diff:
                # proportional penalization for explanation of length below EXPLANATION_MIN_LEN
                score *= 1.0 - (float(expl_diff) / EXPLANATION_MIN_LEN)

        return score


class LLMJudgeWrapper(LLMJudge):
    """wrapper of LLMJudge that retries the prompt for specific exceptions"""

    async def evaluate(self, ctx):
        # how long we sleep before next attempt
        delay = PROMPT_RETRY_503_DELAY_INIT

        # retry loop
        attempt = 0
        while True:
            try:
                # regular evaluation of LLMJudge
                return await super().evaluate(ctx)

            except (ModelHTTPError, ServerError) as e:
                code = e.status_code if isinstance(e, ModelHTTPError) else e.code
                if agent_default_max_retries <= attempt or code not in [500, 503]:
                    # propagate other exceptions (or exceeded retry attempts)
                    raise

                # increment the counter of retries
                attempt += 1

                # print a warning that we retry the prompt
                msg = f"LLMJudge raised an exception: {e}"
                msg += f", retrying in {delay}s"
                msg += f", attempt {attempt}/{agent_default_max_retries}"
                logger.warning(msg)

                # wait before the next attempt
                await asyncio.sleep(delay)

                # gradually increase the delay
                delay *= 2


def create_output_config(name):
    """return a fresh instance of OutputConfig if name is given, False otherwise"""
    return OutputConfig(evaluation_name=name, include_reason=True) if name else False


def create_llm_judge(score_name=None, assertion_name=None, **kwargs):
    """construct an LLMJudge object based on the provided named arguments"""
    return LLMJudgeWrapper(
        model=evals_llm_model,
        model_settings=evals_llm_settings,
        score=create_output_config(score_name),
        assertion=create_output_config(assertion_name),
        **kwargs,
    )


def make_eval_reason(value: bool = False, fail_reason: str = None):  # type: ignore
    """construct EvaluationReason object; fail_reason is propagated only if value is False"""
    return EvaluationReason(value=value, reason=(fail_reason if not value else None))


def eval_name_from_result(result):
    """return human-readable evaluator name associated with the evaluation result"""
    try:
        # This works for our custom evaluators
        return result.name
    except AttributeError:
        # This works for a scoring LLMJudge
        return result.source.arguments["score"]["evaluation_name"]


def _format_suggest_affected_components_output(val: Any) -> str:
    """Format suggest_affected_components output for display: show components only."""
    if val is None:
        return ""
    if hasattr(val, "components") and val.components is not None:
        return str(val.components)
    return str(val)


def _score_with_threshold_indicator(value: float | int) -> str:
    """Format score with pass/fail indicator based on MIN_SCORE_THRESHOLD."""
    if isinstance(value, float) and math.isnan(value):
        return "NaN [red]✗[/]"
    formatted = default_render_number(value)
    indicator = "[green]✔[/]" if value >= MIN_SCORE_THRESHOLD else "[red]✗[/]"
    return f"{formatted} {indicator}"


def _build_score_configs(report: EvaluationReport) -> dict[str, RenderNumberConfig]:
    """Build score_configs so scores display pass/fail indicator in the table."""
    score_names: set[str] = set()
    for case in report.cases:
        score_names.update(case.scores.keys())
    return {
        name: RenderNumberConfig(value_formatter=_score_with_threshold_indicator)
        for name in score_names
    }


def is_evaluator_known_to_fail(ecase, eval_name):
    """return True if the eval_name evaluator is known to fail for the ecase evaluation case"""
    return ecase.metadata and eval_name in ecase.metadata.get(
        "known_to_fail_evaluators", []
    )


def _log_eval_report(report: EvaluationReport) -> str:
    """Log the evaluation report and return any failure messages.

    Always succeeds — logs the rich table, records global summary/metrics,
    and returns a (possibly empty) string of assertion failures.  Callers
    decide whether to raise.
    """
    # capture the report as a string
    string_io = io.StringIO()
    console = Console(file=string_io, force_terminal=True)

    # Truncate output to components only for suggest_affected_components (easier to review)
    output_config: RenderValueConfig | None = None
    if report.name == "suggest_affected_components":
        output_config = RenderValueConfig(
            value_formatter=_format_suggest_affected_components_output
        )

    # Score configs: show pass/fail indicator (✔/✗) based on MIN_SCORE_THRESHOLD
    score_configs = _build_score_configs(report)

    # Only include durations when llm_max_jobs == 1 to avoid misleading timing information
    # in parallel job scenarios, where durations may not be representative.
    report.print(
        console=console,
        include_input=True,
        include_expected_output=True,
        include_output=True,
        include_durations=(get_settings().llm_max_jobs == 1),
        include_reasons=True,
        output_config=output_config,
        score_configs=score_configs,
    )

    # print the captured string through logger
    report_text = string_io.getvalue()
    logger.info(f"evaluation report for {report.name}:\n{report_text}")

    # record evaluation summary to the global dict
    num_evaluated = len(report.cases)
    num_total = num_evaluated + len(report.failures)
    succ_ratio = 100.0 * num_evaluated / num_total if num_total else 0.0
    summary = f"evaluated {num_evaluated} cases of {num_total} ({succ_ratio:.0f}%)"
    eval_summary[report.name] = summary

    # record evaluation metrics to the global dict
    eval_metrics[report.name] = report.averages()

    failures = ""

    # handle case failures (LLM quota exceeded, LLM response timed out, etc.)
    for ecase in report.failures:
        failures += f"{ecase.name}: case failure: {ecase.error_message}\n"

    # iterate through evaluated cases
    for ecase in report.cases:
        # bool assertions
        for result in ecase.assertions.values():
            if result.value is True:
                continue

            if is_evaluator_known_to_fail(ecase, result.name):
                continue

            failures += f"{ecase.name}: {result.name}: {result.value}"
            if result.reason:
                failures += f", reason: {result.reason}"
            failures += "\n"

        # evaluator failures
        for ef in ecase.evaluator_failures:
            failures += f"{ecase.name}: {ef.name}: {ef.error_message}\n"

        # score threshold
        for result in ecase.scores.values():
            score = result.value
            if score < MIN_SCORE_THRESHOLD:
                eval_name = eval_name_from_result(result)
                if is_evaluator_known_to_fail(ecase, eval_name):
                    # this evaluator is known to fail --> no assertion failure
                    continue

                failures += f"{ecase.name}: {eval_name}: score below threshold: "
                failures += f"{score:.4f} < {MIN_SCORE_THRESHOLD}"
                if result.reason:
                    failures += f", reason: {result.reason}"
                failures += "\n"

    return failures


def handle_eval_report(report: EvaluationReport):
    """Print evaluation summary and trigger assertion failure in case any assertion failed."""
    failures = _log_eval_report(report)
    assert not failures, f"Unsatisfied assertion(s):\n{failures}"


async def run_evaluation(
    cases: Sequence[Any],
    evals: Sequence[Any],
    task: Any,
    *,
    max_concurrency: int | None = None,
    agent=None,
    on_report: "Callable[[EvaluationReport, str], None] | None" = None,
) -> EvaluationReport:
    """Create a dataset for the given cases/evaluators and evaluate the given task.

    Pass agent to enable parallel execution: wrapping in ``async with agent`` ensures
    MCP connections are entered/exited in the same task, avoiding anyio cancel-scope
    errors. max_concurrency overrides the default (llm_max_jobs) when provided.

    ``on_report``, when provided, is called with ``(report, failures)``
    **before** the assertion fires.  This guarantees that export/audit
    hooks run even when the eval suite has failures.  Exceptions inside
    the callback are logged but do not suppress the original assertion.

    Returns the EvaluationReport for tests that need to assert on evaluation results.
    """
    dataset = Dataset(
        name=task.__name__,
        cases=cases,
        evaluators=evals,
    )
    debug = logger.isEnabledFor(logging.DEBUG)
    concurrency = (
        max_concurrency if max_concurrency is not None else get_settings().llm_max_jobs
    )

    async def _evaluate():
        return await dataset.evaluate(task, max_concurrency=concurrency, progress=debug)

    if agent is not None:
        async with agent:
            report = await _evaluate()
    else:
        report = await _evaluate()

    failures = _log_eval_report(report)

    if on_report is not None:
        try:
            on_report(report, failures)
        except Exception:
            logger.exception("on_report callback failed (report was still written)")

    assert not failures, f"Unsatisfied assertion(s):\n{failures}"
    return report


class ToolsUsedEvaluator(Evaluator[str, AegisFeatureModel]):
    # Any authoritative CVE data source satisfies this check.  kernel_cve is
    # the primary source for kernel CVEs when the linux-CVE tool is enabled.
    # kernel_impact_tool fetches git patch data from kernel.org/GitHub and
    # counts as evidence that the agent queried an external CVE data source.
    _cve_data_tools = ("osidb_tool", "kernel_cve", "kernel_impact_tool")

    def evaluate(self, ctx) -> EvaluationReason:
        used = ctx.output.tools_used
        hit = any(any(alias in tool for alias in self._cve_data_tools) for tool in used)
        return make_eval_reason(
            hit,
            f"no CVE data tool ({', '.join(self._cve_data_tools)}) was used by the agent",
        )


def _parse_trace(trace: str | None) -> tuple[list[str], list[str]]:
    """Extract rules_fired and guardrails_fired lists from a reconciliation trace."""
    import re

    rules: list[str] = []
    guardrails: list[str] = []
    if trace:
        m = re.search(r"rules=\[([^\]]*)\]", trace)
        if m:
            rules = [r.strip() for r in m.group(1).split(",") if r.strip()]
        m = re.search(r"guardrails=\[([^\]]*)\]", trace)
        if m:
            guardrails = [g.strip() for g in m.group(1).split(",") if g.strip()]
    return rules, guardrails


def export_eval_results(
    report: EvaluationReport,
    output_path: Path,
    *,
    classifier_diagnostics: dict[str, dict | None] | None = None,
) -> Path:
    """Write structured per-case eval results to a JSON file for post-hoc analysis.

    Args:
        report: the evaluation report from pydantic_evals
        output_path: where to write the JSON file
        classifier_diagnostics: optional dict mapping CVE ID -> classifier result dict

    Returns:
        the path written to
    """
    classifier_diagnostics = classifier_diagnostics or {}
    cases_out: list[dict[str, Any]] = []

    for ecase in report.cases:
        output = ecase.output
        expected = ecase.expected_output

        case_data: dict[str, Any] = {
            "cve_id": ecase.inputs,
            "expected_impact": getattr(expected, "impact", None) if expected else None,
            "predicted_impact": getattr(output, "impact", None),
            "predicted_cvss3_score": getattr(output, "cvss3_score", None),
            "predicted_cvss3_vector": getattr(output, "cvss3_vector", None),
            "confidence": getattr(output, "confidence", None),
            "explanation": getattr(output, "explanation", None),
            "deescalation_rationale": getattr(output, "deescalation_rationale", None),
        }

        diag = classifier_diagnostics.get(ecase.inputs)
        if diag is None and hasattr(output, "_classifier_diagnostics"):
            diag = output._classifier_diagnostics
        escalation = getattr(output, "_escalation_floor_applied", False)
        reconciliation_trace = getattr(output, "_reconciliation_trace", None)

        case_data["classifier"] = None
        if diag:
            rules_fired, guardrails_fired = _parse_trace(reconciliation_trace)
            case_data["classifier"] = {
                "impact": diag.get("impact"),
                "confidence": diag.get("confidence"),
                "probabilities": diag.get("probabilities"),
                "active_features": diag.get("active_features"),
                "cvss_score": diag.get("cvss_score"),
                "cvss_vector": diag.get("cvss_vector"),
                "patches_analyzed": diag.get("patches_analyzed"),
                "escalation_floor_applied": escalation,
                "reconciliation_trace": reconciliation_trace,
                "rules_fired": rules_fired,
                "guardrails_fired": guardrails_fired,
            }

        evaluators: dict[str, Any] = {}
        for name, result in ecase.assertions.items():
            evaluators[name] = {
                "passed": result.value,
                "reason": result.reason,
            }
        for name, result in ecase.scores.items():
            evaluators[name] = {"score": result.value}
        case_data["evaluators"] = evaluators

        cases_out.append(case_data)

    for failure in report.failures:
        cases_out.append(
            {
                "cve_id": failure.inputs,
                "error": failure.error_message,
            }
        )

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": report.name,
        "total_cases": len(report.cases) + len(report.failures),
        "evaluated": len(report.cases),
        "failed_to_run": len(report.failures),
        "cases": cases_out,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str) + "\n")
    logger.info("Eval results exported to %s", output_path)
    return output_path


common_feature_evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
]
