"""
Semantic similarity scoring for programmatic feedback.

This module provides async functions to calculate semantic proximity scores
between suggested and submitted values using LLM judge, following the pattern
used in the eval LLM judge code.
"""

import asyncio
import logging
import os
import time
from typing import Optional

from google.genai.errors import ServerError
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from aegis_ai import get_settings

logger = logging.getLogger(__name__)

# Timeout for semantic scoring LLM calls (in seconds)
SEMANTIC_SCORING_TIMEOUT = int(os.getenv("AEGIS_SEMANTIC_SCORING_TIMEOUT", "30"))

# Get LLM model configuration (reuse evals LLM if available, otherwise default)
evals_llm_host = os.getenv("AEGIS_EVALS_LLM_HOST")
if evals_llm_host:
    evals_llm_model_name = os.getenv(
        "AEGIS_EVALS_LLM_MODEL", get_settings().default_llm_model_name
    )
    evals_llm_api_key = os.getenv("AEGIS_EVALS_LLM_API_KEY", "")
    semantic_scoring_model = OpenAIChatModel(
        model_name=evals_llm_model_name,
        provider=OpenAIProvider(
            base_url=f"{evals_llm_host}/v1/",
            api_key=evals_llm_api_key,
        ),
    )
    semantic_scoring_settings = OpenAIResponsesModelSettings()
else:
    # fallback to use the same LLM for semantic scoring
    semantic_scoring_model = get_settings().default_llm_model
    semantic_scoring_settings = get_settings().default_llm_settings


# Feature-specific rubrics for semantic similarity scoring
FEATURE_RUBRICS = {
    "suggest-title": (
        "Score how much the actual suggested_title field is semantically equivalent "
        "to the expected suggest_title field. If the key message is the same but the "
        "style is different, the score should not be zero. If the style is different, "
        "the score should not be 1.0. Return a score between 0.0 and 1.0."
    ),
    "suggest-description": (
        "Score how much the actual suggested_description field is semantically equivalent "
        "to the expected suggest_description field. If the key message is the same but "
        "the style is different, the score should not be zero. If the style is different, "
        "the score should not be 1.0. Return a score between 0.0 and 1.0."
    ),
    "suggest-statement": (
        "Score semantic equivalence between the actual suggested_statement and the expected "
        "suggested_statement. Emphasize matching rationale (impact justification in RH context, "
        "preconditions, scope). If style differs but the core message overlaps, the score should "
        "be > 0.0 and < 1.0 depending on overlap. Only assign 0.0 if the actual is irrelevant "
        "to the CVE or contradicts the expected meaning. When partially aligned but missing details, "
        "prefer a low non-zero score (e.g., 0.12–0.3) rather than 0.0. Return a score between 0.0 and 1.0."
    ),
    "suggest-mitigation": (
        "Score how much the actual suggested_mitigation field is semantically equivalent to the "
        "expected suggested_mitigation field. If the key message is the same but the style is "
        "different, the score should not be zero. If the style is different, the score should "
        "not be 1.0. Return a score between 0.0 and 1.0."
    ),
}


async def calculate_semantic_proximity_score(
    suggested: str, submitted: str, feature: str, cve_id: Optional[str] = None
) -> Optional[float]:
    """
    Calculate semantic proximity score between suggested and submitted values using LLM judge.

    Args:
        suggested: The AI-suggested value
        submitted: The value actually submitted by the user
        feature: The feature name (e.g., 'suggest-title', 'suggest-description')
        cve_id: Optional CVE ID for logging purposes

    Returns:
        A float between 0.0 and 1.0 representing semantic similarity, or None if scoring fails
    """
    if not suggested or not submitted:
        return None

    if feature not in FEATURE_RUBRICS:
        logger.warning(
            f"Semantic scoring not supported for feature '{feature}'. "
            f"Supported features: {list(FEATURE_RUBRICS.keys())}"
        )
        return None

    rubric = FEATURE_RUBRICS[feature]

    # Build the prompt for LLM judge
    prompt = f"""You are evaluating semantic similarity between two text values.

Rubric: {rubric}

Suggested value:
{suggested}

Submitted value:
{submitted}

Provide a semantic similarity score between 0.0 and 1.0, where:
- 1.0 means the values are semantically equivalent
- 0.0 means the values are completely different or contradictory
- Values between 0.0 and 1.0 represent partial semantic similarity

Return only a single floating-point number between 0.0 and 1.0, nothing else."""

    start_time = time.time()
    try:
        # Use asyncio.wait_for to enforce timeout
        result = await asyncio.wait_for(
            _call_llm_for_scoring(prompt),
            timeout=SEMANTIC_SCORING_TIMEOUT,
        )

        end_time = time.time()
        duration = end_time - start_time

        # Parse the result to extract the score
        score = _parse_score_from_response(result)

        # Log performance metrics
        logger.info(
            f"Semantic scoring completed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"score={score}"
        )

        return score

    except asyncio.TimeoutError:
        end_time = time.time()
        duration = end_time - start_time
        logger.warning(
            f"Semantic scoring timed out after {SEMANTIC_SCORING_TIMEOUT}s: "
            f"feature={feature}, cve_id={cve_id or 'N/A'}, duration={duration:.3f}s"
        )
        return None

    except (ModelHTTPError, ServerError, Exception) as e:
        end_time = time.time()
        duration = end_time - start_time
        error_type = type(e).__name__
        logger.error(
            f"Semantic scoring failed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"error={error_type}: {str(e)}"
        )
        return None


async def _call_llm_for_scoring(prompt: str) -> str:
    """
    Call the LLM model to get a semantic similarity score.

    Args:
        prompt: The prompt to send to the LLM

    Returns:
        The LLM response as a string
    """
    # Use pydantic-ai Agent to run the model
    from pydantic_ai import Agent

    agent = Agent(
        model=semantic_scoring_model,
        model_settings=semantic_scoring_settings,
    )

    result = await agent.run(prompt)
    # Extract text from the result
    # When no output_type is specified, result.output is typically a string
    return str(result.output)


def _parse_score_from_response(response: str) -> Optional[float]:
    """
    Parse a floating-point score from the LLM response.

    Args:
        response: The LLM response string

    Returns:
        A float between 0.0 and 1.0, or None if parsing fails
    """
    try:
        # Try to extract a float from the response
        # Remove any whitespace and look for a number
        import re

        # Look for a number between 0.0 and 1.0
        match = re.search(r"\b(0\.\d+|1\.0|0|1)\b", response.strip())
        if match:
            score = float(match.group(1))
            # Clamp to [0.0, 1.0]
            score = max(0.0, min(1.0, score))
            return score
        else:
            logger.warning(f"Could not parse score from LLM response: {response}")
            return None
    except (ValueError, AttributeError) as e:
        logger.warning(f"Error parsing score from response '{response}': {e}")
        return None
