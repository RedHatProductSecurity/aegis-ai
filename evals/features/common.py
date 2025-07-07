from pydantic_evals.evaluators import Evaluator, EvaluatorContext

from aegis.features.data_models import AegisFeatureModel


EXPLANATION_MIN_LEN = 80


class FeatureMetricsEvaluator(Evaluator[str, AegisFeatureModel]):
    def evaluate(self, ctx: EvaluatorContext[str, list[str]]) -> float:
        # multiply all metrics to get overall score to make it simple for now
        # FIXME: should we use separate evaluator for each of them?
        score = ctx.output.confidence * ctx.output.completeness * ctx.output.consistency

        expl_diff = EXPLANATION_MIN_LEN - len(ctx.output.explanation)
        if 0 < expl_diff:
            # proportional penalization for explanation of length below EXPLANATION_MIN_LEN
            score *= 1.0 - (float(expl_diff) / EXPLANATION_MIN_LEN)

        return score


common_feature_evals = [
    FeatureMetricsEvaluator(),
]
