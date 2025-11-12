import pytest
import re
from typing import get_args

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestDescriptionText, SuggestDescriptionModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    make_eval_reason,
    run_evaluation,
)


# some evaluators are only applicable if the expected output for a specific field is provided
field_evaluators = {
    "suggested_title": create_llm_judge(
        score_name="TitleEvaluator",
        rubric="Score how much the actual suggested_title field is semantically equivalent to the expected suggest_title field.",
        include_expected_output=True,
    ),
    "suggested_description": create_llm_judge(
        score_name="DescriptionEvaluator",
        rubric="Score how much the actual suggested_description field is semantically equivalent to the expected suggest_description field.",
        include_expected_output=True,
    ),
}


class SuggestDescriptionCase(Case):
    def __init__(self, cve_id, expected_title=None, expected_description=None):
        """cve_id given as CVE-YYYY-NUM is the flaw we suggest description for."""
        disclaimer_model = SuggestDescriptionModel.model_fields["disclaimer"]
        disclaimer = get_args(disclaimer_model.annotation)[0]
        expected_output = SuggestDescriptionModel(
            cve_id=cve_id,
            components=[],
            explanation="",
            suggested_title=(expected_title or ""),
            suggested_description=(expected_description or ""),
            confidence=1.0,
            tools_used=[],
            disclaimer=disclaimer,
        )

        # enable field-specific evaluators for this case
        evaluators = tuple(
            field_evaluators[f] for f in field_evaluators if getattr(expected_output, f)
        )

        super().__init__(
            name=f"suggest-description-for-{cve_id}",
            inputs=cve_id,
            expected_output=expected_output,
            evaluators=evaluators,
        )


class PromptLeakEvaluator(Evaluator[str, SuggestDescriptionModel]):
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
            ctx.output.suggested_title,
            ctx.output.suggested_description,
        )

    async def evaluate(self, ctx) -> EvaluationReason:
        """check that text from the prompt template does not leak into the response"""

        # a list of unwanted regular expressions we chek for
        check_list = [
            r"'component.name'",
            r"\[impact\]",
            r"\[vector\]",
        ]

        # go through the list of regexes one by one
        for r in check_list:
            if self._match_re_in_td(ctx, r):
                return make_eval_reason(
                    fail_reason=f'"{r}" appears in title or description'
                )

        # no match
        return EvaluationReason(True)


async def suggest_description(cve_id: CVEID) -> SuggestDescriptionModel:
    """use rh_feature_agent to suggest description for the given CVE"""
    feature = SuggestDescriptionText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestDescriptionCase(
        # not vetted by a PSIRT analyst
        cve_id="CVE-2025-5399",
        expected_title="WebSocket endless loop",
        expected_description="A flaw was found in libcurl. This vulnerability allows a denial of service via a crafted WebSocket packet from a malicious server.",
    ),
    SuggestDescriptionCase(
        # not vetted by a PSIRT analyst
        cve_id="CVE-2025-23395",
        expected_title="Local Root Exploit via `logfile_reopen()`",
        expected_description="A flaw was found in Screen. When running with setuid-root privileged, the  logfile_reopen() function does not drop privileges while operating on a user-supplied path. This vulnerability allows an unprivileged user to create files in arbitrary locations with root ownership.",
    ),
    # TODO: add more cases
]

# evaluators
evals = common_feature_evals + [
    PromptLeakEvaluator(),
    create_llm_judge(
        rubric="suggested_title and suggested_description do not contain any versioning info"
    ),
    create_llm_judge(
        rubric="suggested_title briefly summarizes what is described in suggested_description"
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_description():
    """suggest_description evaluation entry point"""
    await run_evaluation(cases, evals, suggest_description)
