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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "notes, description, statement",
    [
        pytest.param(
            "Internal only: a malformed frame triggers a decoder crash.",
            "A flaw affects the frame decoder.",
            "",
            id="trigger-only-in-private-notes",
        ),
        pytest.param(
            "Internal only: a malformed frame triggers a decoder crash.",
            "A malformed frame can crash the frame decoder.",
            "The decoder can be crashed by a malformed frame.",
            id="trigger-also-in-public-content",
        ),
        pytest.param(None, "A flaw affects the frame decoder.", "", id="no-notes"),
        pytest.param("", "A flaw affects the frame decoder.", "", id="empty-notes"),
    ],
)
async def test_quality_review_scoring_evidence_policy_reaches_model(
    monkeypatch, notes, description, statement
):
    """Check the instruction, not the canned model's ability to follow it."""
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
    references = ["https://example.org/advisories/frame-decoder"]
    private_comments = ["Internal triage: the decoder runs only when enabled."]
    result = await review.exec(
        CVE_ID,
        static_context={
            "description": description,
            "statement": statement,
            "references": references,
            "comments": private_comments,
            "steering_notes": notes,
        },
    )

    prompts = [
        part.content
        for message in result.all_messages()
        if isinstance(message, ModelRequest)
        for part in message.parts
        if isinstance(part, UserPromptPart)
    ]
    assert len(prompts) == 1
    prompt = prompts[0]
    assert isinstance(prompt, str)
    instructions, separator, context = prompt.partition("\n\nContext:\n")
    assert separator
    context = context.partition("\n\nFormat:")[0]
    assert f"description={description!r}" in context
    assert f"statement={statement!r}" in context
    assert f"references={references!r}" in context
    assert f"comments={private_comments!r}" in context
    if notes is None:
        assert "steering_notes=" not in context
    else:
        assert f"steering_notes={notes!r}" in context

    rules = [
        " ".join(rule.lower().replace("`", "").split())
        for rule in re.split(r"\n\s*-\s+", instructions)
    ]
    evidence_rule = next(
        (
            rule
            for rule in rules
            if "existing customer-visible flaw content as evidence" in rule
        ),
        "",
    )
    assert evidence_rule, (
        "Scoring must be grounded in existing customer-visible content"
    )
    for output in (
        "all rubric scores and justifications",
        "strengths",
        "critical gaps",
        "value_add",
        "customer lens assessments",
    ):
        assert output in evidence_rule, f"Evidence restriction must cover {output}"
    assert "publicly accessible references" in evidence_rule
    for excluded_source in (
        "steering_notes",
        "other non-public data",
        "proposed rewrites",
    ):
        assert excluded_source in evidence_rule
    assert "do not treat" in evidence_rule
    assert "as existing customer-visible content" in evidence_rule

    missing_rule = next(
        (
            rule
            for rule in rules
            if "information appears only in steering_notes" in rule
        ),
        "",
    )
    assert "other non-public data" in missing_rule
    assert "treat it as missing from the customer-visible content" in missing_rule
    assert "score the relevant criteria accordingly" in missing_rule
    assert "what remains unclear or needs manual context" in missing_rule
    assert "do not assume customers can see or infer it" in missing_rule

    # The restriction must coexist with the full rubric and conditional rewrites.
    rubric = instructions.partition("### RUBRIC CATEGORIES")[2].partition(
        "### STATEMENT RULES"
    )[0]
    assert len(re.findall(r"\*\*Category [1-6]:", rubric)) == 6
    assert "score ALL 30 criteria" in rubric
    assert "If the statement scores below 6/10" in instructions
    assert "If the mitigation scores below 6/10" in instructions
    assert "For rejected flaws" in instructions
