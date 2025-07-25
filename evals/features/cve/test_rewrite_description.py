import pytest
import re

from pydantic_evals import Case, Dataset
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import RewriteDescriptionText, RewriteDescriptionModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    handle_eval_report,
    make_eval_reason,
)
from evals.utils.osidb_cache import osidb_cache_retrieve


class RewriteDescriptionCase(Case):
    def __init__(self, cve_id):
        """cve_id given as CVE-YYYY-NUM is the flaw we rewrite description for."""
        super().__init__(
            name=f"rewrite-description-for-{cve_id}",
            inputs=cve_id,
            expected_output=None,
            metadata={"difficulty": "easy"},
        )


class OriginalTitleEvaluator(Evaluator[str, RewriteDescriptionModel]):
    async def evaluate(self, ctx) -> EvaluationReason:
        """check whether original title is propagated by the model"""
        cve = await osidb_cache_retrieve(ctx.inputs)
        return make_eval_reason(
            ctx.output.original_title == cve.title,
            "original_title does not match original title",
        )


class PromptLeakEvaluator(Evaluator[str, RewriteDescriptionModel]):
    @staticmethod
    def _match_re_in(pat, *args) -> bool:
        """look for regular expression pat (case insensitively) in the arguments"""
        for text in args:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _match_re_in_td(ctx, pat) -> bool:
        """look for regular expression pat (case insensitively) in title or description"""
        return PromptLeakEvaluator._match_re_in(
            pat,
            ctx.output.rewritten_title,
            ctx.output.rewritten_description,
        )

    async def evaluate(self, ctx) -> EvaluationReason:
        """check that text from the prompt template does not leak into the response"""
        if self._match_re_in_td(ctx, r"'component.name'"):
            return make_eval_reason(
                fail_reason="'component_name' appears in title or description"
            )

        if self._match_re_in_td(ctx, r"gluster"):
            return make_eval_reason(
                fail_reason="'gluster' appears in title or description"
            )

        if self._match_re_in_td(ctx, r"samba"):
            return make_eval_reason(
                fail_reason="'samba' appears in title or description"
            )

        return EvaluationReason(True)


async def rewrite_description(cve_id: CVEID) -> RewriteDescriptionModel:
    """use rh_feature_agent to rewrite description for the given CVE"""
    feature = RewriteDescriptionText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    RewriteDescriptionCase("CVE-2025-23395"),
    RewriteDescriptionCase("CVE-2025-5399"),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    OriginalTitleEvaluator(),
    PromptLeakEvaluator(),
    create_llm_judge(
        rubric="rewritten_title and rewritten_description do not contain any versioning info"
    ),
    create_llm_judge(
        rubric="rewritten_title briefly summarizes what is described in rewritten_description"
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_rewrite_description():
    """rewrite_description evaluation entry point"""
    dataset = Dataset(cases=cases, evaluators=evals)
    report = await dataset.evaluate(rewrite_description)
    handle_eval_report(report)
