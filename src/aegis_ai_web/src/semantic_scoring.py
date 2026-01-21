"""
Semantic similarity scoring for programmatic feedback.

This module provides async functions to calculate semantic proximity scores
between suggested and submitted values, reusing evaluators from the evals
directory to maintain consistency between CI-triggered evaluation and
OSIM-triggered evaluation/scoring.
"""

import asyncio
import json
import logging
import os
import time
from typing import Optional

from google.genai.errors import ServerError
from pydantic_ai.exceptions import ModelHTTPError

# Reuse evaluators and utilities from evals
from evals.features.common import create_llm_judge, FIELD_RUBRICS
from evals.features.cve.test_suggest_cwe import SuggestCweEvaluator
from evals.features.cve.test_suggest_impact import score_cvss3_diff

logger = logging.getLogger(__name__)

# Timeout for semantic scoring LLM calls (in seconds)
AEGIS_LLM_TIMEOUT_SECS = int(os.getenv("AEGIS_LLM_TIMEOUT_SECS", "30"))


def get_semantic_scored_features() -> list[str]:
    """
    Return the list of features that support semantic scoring.

    This is the single source of truth for which features can be
    semantically scored.
    """
    return list(FIELD_RUBRICS.keys()) + ["suggest-cwe", "suggest-impact"]


def _parse_json_list(value: str) -> Optional[list[str]]:
    """
    Parse a JSON list from a string value.

    Args:
        value: String that may contain a JSON list

    Returns:
        Parsed list of strings, or None if parsing fails
    """
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
        return None
    except (json.JSONDecodeError, TypeError):
        return None


def _score_cwe_lists(suggested: list[str], submitted: list[str]) -> float:
    """
    Score similarity between two CWE lists using SuggestCweEvaluator logic.

    Args:
        suggested: List of suggested CWEs
        submitted: List of submitted CWEs

    Returns:
        Score between 0.0 and 1.0
    """
    # Reuse the scoring logic from SuggestCweEvaluator
    score = SuggestCweEvaluator._base_score(suggested, submitted)

    # Apply length penalty if suggested list is longer
    len_diff = len(suggested) - len(submitted)
    if 0 < len_diff:
        # penalize too many suggested CWEs
        score *= 0.9**len_diff

    return score


def _is_cvss_vector(value: str) -> bool:
    """
    Check if a string looks like a CVSS vector.

    The suggest-impact feature can receive either CVSS vector strings (e.g.,
    "CVSS:3.1/AV:N/AC:L/...") or simple impact severity strings (e.g., "CRITICAL",
    "HIGH"). Semantic CVSS scoring only applies to actual vectors; simple severity
    strings should fall back to exact-match comparison.

    Args:
        value: String to check

    Returns:
        True if the string appears to be a CVSS vector, False otherwise
    """
    # CVSS vectors start with "CVSS:" prefix or contain metric:value pairs
    if value.startswith("CVSS:"):
        return True
    # Check for typical CVSS metric patterns like AV:N, AC:L, etc.
    if "/" in value and ":" in value:
        parts = value.split("/")
        # CVSS vectors have multiple metric:value pairs
        return len(parts) >= 2 and all(":" in p for p in parts if p)
    return False


def _score_cvss_vectors(
    suggested: str, submitted: str
) -> tuple[Optional[float], Optional[str]]:
    """
    Score similarity between two CVSS vectors using score_cvss3_diff.

    Returns None for the score when values are not valid CVSS vectors, allowing
    the caller to fall back to exact-match scoring. This handles cases where
    suggest-impact receives simple severity strings like "CRITICAL" instead of
    full CVSS vectors.

    Args:
        suggested: Suggested CVSS vector string
        submitted: Submitted CVSS vector string

    Returns:
        Tuple of (score, reason) where score is between 0.0 and 1.0,
        or (None, reason) if the values are not valid CVSS vectors
    """
    # Check if both values look like CVSS vectors
    if not _is_cvss_vector(suggested) or not _is_cvss_vector(submitted):
        logger.debug(
            f"Values are not CVSS vectors, skipping semantic scoring: "
            f"suggested={suggested[:50]}, submitted={submitted[:50]}"
        )
        return (None, "values are not CVSS vectors")

    try:
        return score_cvss3_diff(suggested, submitted)
    except Exception as e:
        logger.warning(f"Error scoring CVSS vectors: {e}")
        return (None, f"unhandled exception: {e}")


async def _score_with_llm_judge(
    suggested: str, submitted: str, rubric: str
) -> Optional[float]:
    """
    Score semantic similarity using LLMJudge from evals.

    Args:
        suggested: The suggested value
        submitted: The submitted value
        rubric: The scoring rubric

    Returns:
        Score between 0.0 and 1.0, or None if scoring fails
    """
    # Create an LLMJudge using the same configuration as evals
    # include_expected_output=True tells LLMJudge to compare input with expected_output
    judge = create_llm_judge(
        score_name="SemanticScoring",
        rubric=rubric,
        include_expected_output=True,
    )

    # Create a context object that matches what LLMJudge expects
    # LLMJudge expects ctx.input (the actual output) and ctx.expected_output
    class SimpleContext:
        """Minimal context wrapper for LLMJudge."""

        def __init__(self, input_val: str, expected_output: str):
            # For LLMJudge, input is the actual output and expected_output is what we compare against
            self.input = input_val  # This will be treated as the actual output
            self.expected_output = expected_output

    # Note: LLMJudge compares ctx.input (actual) with ctx.expected_output (expected)
    # In our case: suggested is the actual output, submitted is what user expects
    ctx = SimpleContext(input_val=suggested, expected_output=submitted)

    try:
        # Use asyncio.wait_for to enforce timeout
        result = await asyncio.wait_for(
            judge.evaluate(ctx),
            timeout=AEGIS_LLM_TIMEOUT_SECS,
        )

        # Extract score from the result
        # LLMJudge returns different types depending on configuration
        if isinstance(result, float):
            return max(0.0, min(1.0, result))
        elif hasattr(result, "value"):
            # EvaluationReason or similar
            score = result.value
            return (
                max(0.0, min(1.0, score)) if isinstance(score, (int, float)) else None
            )
        else:
            logger.warning(f"Unexpected LLMJudge result type: {type(result)}")
            return None

    except asyncio.TimeoutError:
        logger.warning(f"LLMJudge timed out after {AEGIS_LLM_TIMEOUT_SECS}s")
        return None
    except (ModelHTTPError, ServerError, Exception) as e:
        error_type = type(e).__name__
        logger.debug(f"LLMJudge failed: {error_type}: {str(e)}")
        return None


async def calculate_semantic_proximity_score(
    suggested: str, submitted: str, feature: str, cve_id: Optional[str] = None
) -> Optional[float]:
    """
    Calculate semantic proximity score between suggested and submitted values.

    Reuses evaluators from evals directory to maintain consistency between
    CI-triggered evaluation and OSIM-triggered evaluation/scoring.

    Args:
        suggested: The AI-suggested value (may be JSON for CWE lists)
        submitted: The value actually submitted by the user (may be JSON for CWE lists)
        feature: The feature name (e.g., 'suggest-title', 'suggest-cwe', 'suggest-impact')
        cve_id: Optional CVE ID for logging purposes

    Returns:
        A float between 0.0 and 1.0 representing semantic similarity, or None if scoring fails
    """
    if not suggested or not submitted:
        return None

    start_time = time.time()

    try:
        # Handle CWE list scoring
        if feature == "suggest-cwe":
            suggested_list = _parse_json_list(suggested)
            submitted_list = _parse_json_list(submitted)

            if suggested_list is None or submitted_list is None:
                logger.warning(
                    f"Failed to parse CWE lists as JSON: "
                    f"suggested={suggested[:100]}, submitted={submitted[:100]}"
                )
                return None

            score = _score_cwe_lists(suggested_list, submitted_list)

        # Handle CVSS vector scoring
        elif feature == "suggest-impact":
            # Try to extract CVSS vector from JSON if present
            suggested_vector = suggested
            submitted_vector = submitted

            # Check if values are JSON objects with cvss3_vector field
            try:
                suggested_json = json.loads(suggested)
                if (
                    isinstance(suggested_json, dict)
                    and "cvss3_vector" in suggested_json
                ):
                    suggested_vector = suggested_json["cvss3_vector"]
            except (json.JSONDecodeError, TypeError):
                pass

            try:
                submitted_json = json.loads(submitted)
                if (
                    isinstance(submitted_json, dict)
                    and "cvss3_vector" in submitted_json
                ):
                    submitted_vector = submitted_json["cvss3_vector"]
            except (json.JSONDecodeError, TypeError):
                pass

            score, _ = _score_cvss_vectors(suggested_vector, submitted_vector)
            if score is None:
                return None

        # Handle text-based features with LLMJudge
        elif feature in FIELD_RUBRICS:
            rubric = FIELD_RUBRICS[feature]
            score = await _score_with_llm_judge(suggested, submitted, rubric)
            if score is None:
                return None

        else:
            logger.warning(
                f"Semantic scoring not supported for feature '{feature}'. "
                f"Supported features: {get_semantic_scored_features()}"
            )
            return None

        end_time = time.time()
        duration = end_time - start_time

        # Log performance metrics
        logger.info(
            f"Semantic scoring completed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"score={score}"
        )

        return score

    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        error_type = type(e).__name__
        logger.debug(
            f"Semantic scoring failed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"error={error_type}: {str(e)}"
        )
        return None
