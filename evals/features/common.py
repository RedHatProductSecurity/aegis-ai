import asyncio
import io
import logging
import os

from rich.console import Console
from typing import Sequence, Any

from google.genai.errors import ServerError
from pydantic_ai.exceptions import ModelHTTPError
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

from aegis_ai import get_settings
from aegis_ai.agents import agent_default_max_retries
from aegis_ai.features import llm_max_jobs, PROMPT_RETRY_503_DELAY_INIT
from aegis_ai.features.data_models import AegisFeatureModel


# minimal acceptable length of an explanation (where applicable)
EXPLANATION_MIN_LEN = 80

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

# evaluation metrics (dict of ReportCaseAggregate objects)
eval_metrics = {}


logger = logging.getLogger(__name__)


# if AEGIS_EVALS_LLM_HOST is set, use an independent LLM for evals
evals_llm_host = os.getenv("AEGIS_EVALS_LLM_HOST")
if evals_llm_host:
    # use an independent LLM for evals
    evals_llm_model_name = os.getenv(
        "AEGIS_EVALS_LLM_MODEL", get_settings().default_llm_model_name
    )
    evals_llm_api_key = os.getenv("AEGIS_EVALS_LLM_API_KEY", "")
    evals_llm_model = OpenAIChatModel(
        model_name=evals_llm_model_name,
        provider=OpenAIProvider(
            base_url=f"{evals_llm_host}/v1/",
            api_key=evals_llm_api_key,
        ),
    )
    evals_llm_settings = OpenAIResponsesModelSettings()
else:
    # fallback to use the same LLM for evals
    evals_llm_model = get_settings().default_llm_model
    evals_llm_settings = get_settings().default_llm_settings


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
                if agent_default_max_retries <= attempt or code != 503:
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


def is_evaluator_known_to_fail(ecase, eval_name):
    """return True if the eval_name evaluator is known to fail for the ecase evaluation case"""
    return ecase.metadata and eval_name in ecase.metadata.get(
        "known_to_fail_evaluators", []
    )


def handle_eval_report(report: EvaluationReport):
    """print evaluation summary and trigger assertion failure in case any assertion failed"""
    # capture the report as a string
    string_io = io.StringIO()
    console = Console(file=string_io, force_terminal=True)

    # Only include durations when llm_max_jobs == 1 to avoid misleading timing information
    # in parallel job scenarios, where durations may not be representative.
    report.print(
        console=console,
        include_input=True,
        include_expected_output=True,
        include_output=True,
        include_durations=(llm_max_jobs == 1),
        include_reasons=True,
    )

    # print the captured string through logger
    report_text = string_io.getvalue()
    logger.info(f"evaluation report for {report.name}:\n{report_text}")

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
            if result.value is False:
                failures += f"{ecase.name}: {result.name}: False"
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

    # report all failures at once (if any)
    assert not failures, f"Unsatisfied assertion(s):\n{failures}"


async def run_evaluation(cases: Sequence[Any], evals: Sequence[Any], task: Any) -> None:
    """create a dataset for the given cases/evaluators and evaluate the given task"""
    dataset = Dataset(cases=cases, evaluators=evals)
    debug = logger.isEnabledFor(logging.DEBUG)
    report = await dataset.evaluate(task, max_concurrency=llm_max_jobs, progress=debug)
    handle_eval_report(report)


class ToolsUsedEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx) -> EvaluationReason:
        return make_eval_reason(
            any("osidb_tool" in tool for tool in ctx.output.tools_used),
            "osidb_tool was not used by the agent",
        )


common_feature_evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
]
