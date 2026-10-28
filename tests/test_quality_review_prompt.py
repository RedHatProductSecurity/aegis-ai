"""Check steering-note privacy policy in the delivered QualityReview prompt."""

import json
import re

import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelRequest, UserPromptPart
from pydantic_ai.models.test import TestModel

from aegis_ai import get_settings
from aegis_ai.features.cve import QualityReview
from aegis_ai.features.cve.data_models import QualityReviewModel
from tests.utils.llm_cache import get_cached_response

CVE_ID = "CVE-2025-0725"


@pytest.mark.asyncio
async def test_quality_review_keeps_steering_notes_internal_in_rewrites(monkeypatch):
    monkeypatch.setattr(get_settings(), "safety_enabled", False)
    cached_response = get_cached_response("test_quality_review_with_test_model")
    assert cached_response is not None
    review = QualityReview(
        Agent(
            model=TestModel(
                call_tools=[], custom_output_args=json.loads(cached_response)
            )
        )
    )
    notes = (
        "Private analyst note: inspect the optional frame decoder.\n"
        "Keep the analyst's draft internal."
    )

    result = await review.exec(CVE_ID, static_context={"steering_notes": notes})

    assert isinstance(result.output, QualityReviewModel)
    prompts = [
        part.content
        for message in result.all_messages()
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, UserPromptPart)
    ]
    assert len(prompts) == 1, "A valid cached response should need no output retries"
    prompt = prompts[0]
    assert isinstance(prompt, str)
    instructions, separator, context = prompt.partition("\n\nContext:\n")
    assert separator, "The model must receive the CVE context"
    context = context.partition("\n\nFormat:")[0]
    assert f"steering_notes={notes!r}" in context

    rules = [
        " ".join(rule.lower().replace("`", "").replace("–", "-").split())
        for rule in re.split(r"\n\s*-\s+", instructions)
    ]
    policy = next((rule for rule in rules if "steering_notes" in rule), "")
    assert "only as internal guidance" in policy
    assert "do not quote or paraphrase" in policy
    assert "suggested_statement" in policy
    assert "suggested_mitigation" in policy
    assert any(
        "2-4 concise sentences" in rule and "< 1000 characters total" in rule
        for rule in rules
    ), "The existing statement rewrite length requirement must still reach the model"
