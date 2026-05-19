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
import time
from typing import Optional

from aegis_ai import get_settings

# Reuse evaluators and utilities from evals
from evals.features.common import create_llm_judge, FIELD_RUBRICS
from evals.features.cve.test_suggest_cwe import SuggestCweEvaluator
from evals.features.cve.test_suggest_impact import score_cvss3_diff, score_impact_diff

logger = logging.getLogger(__name__)

# Timeout for semantic scoring LLM calls (in seconds)
AEGIS_LLM_TIMEOUT_SECS = get_settings().default_llm_prompt_timeout


def get_semantic_scored_features() -> list[str]:
    """
    Return the list of features that support semantic scoring.

    This is the single source of truth for which features can be
    semantically scored.
    """
    return list(FIELD_RUBRICS.keys()) + [
        "suggest-affected-components",
        "suggest-cwe",
        "suggest-cvss",
        "suggest-impact",
    ]


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


def _score_component_lists(suggested: list[str], submitted: list[str]) -> float:
    """
    Score similarity between two component lists using Jaccard similarity.

    Args:
        suggested: List of suggested component names
        submitted: List of submitted component names

    Returns:
        Score between 0.0 and 1.0
    """
    suggested_set = {n.lower().strip() for n in suggested if n}
    submitted_set = {n.lower().strip() for n in submitted if n}

    if not submitted_set:
        return 1.0 if not suggested_set else 0.0

    if suggested_set == submitted_set:
        return 1.0

    inter = len(suggested_set & submitted_set)
    union = len(suggested_set | submitted_set)
    return inter / union if union else 0.0


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
) -> tuple[float, Optional[str]]:
    """
    Score semantic similarity using LLMJudge from evals.

    Args:
        suggested: The suggested value
        submitted: The submitted value
        rubric: The scoring rubric

    Returns:
        Tuple of (score, explanation) where score is between 0.0 and 1.0
        and explanation is the reasoning provided by LLMJudge

    Raises:
        asyncio.TimeoutError: If the LLM call times out
        TypeError: If LLMJudge returns an unexpected result type
        Exception: Various LLM-related exceptions (HTTP errors, server errors, etc.)
    """
    # Create an LLMJudge using the same configuration as evals
    # include_expected_output=True tells LLMJudge to compare input with expected_output
    judge = create_llm_judge(
        score_name="SemanticScoring",
        rubric=rubric,
        include_expected_output=True,
    )

    # Create a context object that matches what LLMJudge expects
    # LLMJudge with include_expected_output=True calls judge_output_expected(ctx.output, ctx.expected_output, ...)
    class SimpleContext:
        """Minimal context wrapper for LLMJudge."""

        def __init__(self, output: str, expected_output: str):
            # For LLMJudge, output is the actual output and expected_output is what we compare against
            self.output = output  # The actual output (suggested value from AI)
            self.expected_output = expected_output  # What user submitted (ground truth)

    # LLMJudge compares ctx.output (actual) with ctx.expected_output (expected)
    # In our case: suggested is the actual AI output, submitted is what user expects/ground truth
    ctx = SimpleContext(output=suggested, expected_output=submitted)

    # Use asyncio.wait_for to enforce timeout
    result = await asyncio.wait_for(
        judge.evaluate(ctx),
        timeout=AEGIS_LLM_TIMEOUT_SECS,
    )

    # Extract score from the result
    # LLMJudge returns different types depending on configuration:
    # - With score_name="X": returns dict {"X": EvaluationReason(value=..., reason=...)}
    # - Without score_name: may return float or EvaluationReason directly
    if isinstance(result, dict):
        # Result is a dict with score_name as key, e.g., {"SemanticScoring": EvaluationReason(...)}
        if not result:
            raise TypeError("LLMJudge returned empty dict")
        # Get the first (and typically only) value from the dict
        eval_result = next(iter(result.values()))
        if hasattr(eval_result, "value"):
            score = eval_result.value
            explanation = getattr(eval_result, "reason", "")
            if isinstance(score, (int, float)):
                return (max(0.0, min(1.0, float(score))), explanation)
            raise TypeError(
                f"LLMJudge dict result value is not numeric: got {type(score).__name__}"
            )
        raise TypeError(
            f"LLMJudge dict value has no 'value' attribute: got {type(eval_result).__name__}"
        )
    elif isinstance(result, float):
        return (max(0.0, min(1.0, result)), None)
    elif hasattr(result, "value"):
        # EvaluationReason or similar
        score = result.value
        explanation = getattr(result, "reason", None)
        if isinstance(score, (int, float)):
            return (max(0.0, min(1.0, float(score))), explanation)
        raise TypeError(
            f"LLMJudge result.value is not numeric: got {type(score).__name__}"
        )
    else:
        raise TypeError(f"Unexpected LLMJudge result type: {type(result).__name__}")


async def calculate_semantic_proximity_score(
    suggested: str, submitted: str, feature: str, cve_id: Optional[str] = None
) -> tuple[Optional[float], Optional[str]]:
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
        A tuple of (score, explanation) where:
        - score is a float between 0.0 and 1.0 representing semantic similarity, or None if scoring fails
        - explanation is a string describing the reasoning, or None if not available
    """
    if not suggested or not submitted:
        return (None, None)

    start_time = time.time()

    try:
        score: Optional[float] = None
        explanation: Optional[str] = None
        # Handle component list scoring
        if feature == "suggest-affected-components":
            suggested_list = _parse_json_list(suggested)
            submitted_list = _parse_json_list(submitted)

            if suggested_list is None or submitted_list is None:
                logger.warning(
                    f"Failed to parse component lists as JSON: "
                    f"suggested={suggested[:100]}, submitted={submitted[:100]}"
                )
                return (None, None)

            score = _score_component_lists(suggested_list, submitted_list)

        # Handle CWE list scoring
        elif feature == "suggest-cwe":
            suggested_list = _parse_json_list(suggested)
            submitted_list = _parse_json_list(submitted)

            if suggested_list is None or submitted_list is None:
                logger.warning(
                    f"Failed to parse CWE lists as JSON: "
                    f"suggested={suggested[:100]}, submitted={submitted[:100]}"
                )
                return (None, None)

            score = _score_cwe_lists(suggested_list, submitted_list)

        # Handle CVSS vector scoring
        elif feature == "suggest-cvss":
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

            score, reason = _score_cvss_vectors(suggested_vector, submitted_vector)
            if score is None:
                logger.warning(
                    f"CVSS vector scoring returned None: feature={feature}, "
                    f"cve_id={cve_id or 'N/A'}, reason={reason}, "
                    f"suggested_vector={suggested_vector[:100]}, "
                    f"submitted_vector={submitted_vector[:100]}"
                )
                return (None, None)
            explanation = reason

        # Handle impact severity scoring (e.g., CRITICAL, IMPORTANT, MODERATE, LOW, NONE)
        # or CVSS vectors if they look like CVSS format
        elif feature == "suggest-impact":
            # First check if these are CVSS vectors
            if _is_cvss_vector(suggested) and _is_cvss_vector(submitted):
                score, reason = _score_cvss_vectors(suggested, submitted)
                if score is None:
                    logger.warning(
                        f"CVSS vector scoring returned None: feature={feature}, "
                        f"cve_id={cve_id or 'N/A'}, reason={reason}, "
                        f"suggested={suggested[:100]}, "
                        f"submitted={submitted[:100]}"
                    )
                    return (None, None)
                explanation = reason
            else:
                # Use severity string scoring
                try:
                    score = score_impact_diff(suggested, submitted)
                except KeyError as e:
                    logger.warning(f"Invalid impact severity value: {e}")
                    return (None, None)

        # Handle text-based features with LLMJudge
        elif feature in FIELD_RUBRICS:
            rubric = FIELD_RUBRICS[feature]
            score, explanation = await _score_with_llm_judge(
                suggested, submitted, rubric
            )

        else:
            logger.warning(
                f"Semantic scoring not supported for feature '{feature}'. "
                f"Supported features: {get_semantic_scored_features()}"
            )
            return (None, None)

        end_time = time.time()
        duration = end_time - start_time

        # Log performance metrics
        logger.info(
            f"Semantic scoring completed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"score={score}"
        )

        return (score, explanation)

    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        error_type = type(e).__name__
        logger.warning(
            f"Semantic scoring failed: feature={feature}, "
            f"cve_id={cve_id or 'N/A'}, duration={duration:.3f}s, "
            f"error={error_type}: {str(e)}"
        )
        logger.debug(f"Semantic scoring error details for {cve_id}", exc_info=True)
        return (None, None)
