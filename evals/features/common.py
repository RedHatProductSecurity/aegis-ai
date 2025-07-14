from pydantic_evals.evaluators import EvaluationReason, Evaluator, EvaluatorContext

from aegis.features.data_models import AegisFeatureModel


EXPLANATION_MIN_LEN = 80


class FeatureMetricsEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx: EvaluatorContext[str, AegisFeatureModel]) -> float:
        # multiply all metrics to get overall score to make it simple for now
        # FIXME: should we use separate evaluator for each of them?
        score = ctx.output.confidence * ctx.output.completeness * ctx.output.consistency

        expl_diff = EXPLANATION_MIN_LEN - len(ctx.output.explanation)
        if 0 < expl_diff:
            # proportional penalization for explanation of length below EXPLANATION_MIN_LEN
            score *= 1.0 - (float(expl_diff) / EXPLANATION_MIN_LEN)

        return score


def make_eval_reason(value: bool = False, fail_reason: str = None):
    """construct EvaluationReason object; fail_reason is propagated only if value is False"""
    # FIXME: the reason for an assertion failure is not reported anywhere
    return EvaluationReason(value=value, reason=(fail_reason if not value else None))


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
