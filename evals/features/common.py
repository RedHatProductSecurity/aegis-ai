from pydantic_evals.dataset import EvaluationReport
from pydantic_evals.evaluators import (
    EvaluationReason,
    Evaluator,
    EvaluatorContext,
    LLMJudge,
)

from aegis_ai import default_llm_model, default_llm_settings
from aegis_ai.features.data_models import AegisFeatureModel


# minimal acceptable length of an explanation (where applicable)
EXPLANATION_MIN_LEN = 80

# minimal acceptable score returned by an evaluator
MIN_SCORE_THRESHOLD = 0.1


class FeatureMetricsEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx: EvaluatorContext[str, AegisFeatureModel]) -> float:
        # multiply all metrics to get overall score to make it simple for now
        # FIXME: should we use separate evaluator for each of them?
        score = ctx.output.confidence * ctx.output.completeness * ctx.output.consistency

        # do not check explanation length for IdentifyPII and CVSSDiffExplainer because
        # the explanation is empty in the most common case
        if not hasattr(ctx.output, "contains_PII") and not hasattr(
            ctx.output, "nvd_cvss3_score"
        ):
            expl_diff = EXPLANATION_MIN_LEN - len(ctx.output.explanation)
            if 0 < expl_diff:
                # proportional penalization for explanation of length below EXPLANATION_MIN_LEN
                score *= 1.0 - (float(expl_diff) / EXPLANATION_MIN_LEN)

        return score


def create_llm_judge(**kwargs):
    """construct an LLMJudge object based on the provided named arguments"""
    return LLMJudge(
        # TODO: we might consider using an independent LLM for evals
        model=default_llm_model,
        model_settings=default_llm_settings,
        **kwargs,
    )


def make_eval_reason(value: bool = False, fail_reason: str = None):
    """construct EvaluationReason object; fail_reason is propagated only if value is False"""
    # FIXME: the reason for an assertion failure is not reported anywhere
    return EvaluationReason(value=value, reason=(fail_reason if not value else None))


def handle_eval_report(report: EvaluationReport):
    """print evaluation summary and trigger assertion failure in case any assertion failed"""
    report.print(include_input=True, include_output=True, include_durations=False)

    # iterate through cases
    failures = ""
    for case in report.cases:
        # bool assertions
        for result in case.assertions.values():
            if result.value is False:
                failures += f"{case.name}: {result.source}: {result.reason}\n"

        # score threshold
        for result in case.scores.values():
            score = result.value
            if score < MIN_SCORE_THRESHOLD:
                failures += f"{case.name}: {result.source}: score below threshold: "
                failures += f"{score} < {MIN_SCORE_THRESHOLD}\n"

    # report all failures at once (if any)
    assert not failures, f"Unsatisfied assertion(s):\n{failures}"


class ToolsUsedEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx) -> EvaluationReason:
        return make_eval_reason(
            "osidb_tool" in ctx.output.tools_used,
            "osidb_tool was not used by the agent",
        )


common_feature_evals = [
    FeatureMetricsEvaluator(),
    ToolsUsedEvaluator(),
]
