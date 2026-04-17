import asyncio
import csv
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app
from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

client = TestClient(app)


def test_save_programmatic_feedback_success(programmatic_feedback_log_setup):
    """
    Test a successful programmatic feedback submission with valid data.
    Acceptance score should be calculated server-side (None for non-matching values).
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "joey@redhat.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200
    assert response.json() == {
        "status": "Programmatic feedback received and logged successfully."
    }

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0, "No rows found in programmatic feedback log"
            last_row = rows[-1]
            assert last_row["feature"] == "suggest-impact"
            assert last_row["cve_id"] == "CVE-2025-23395"
            assert last_row["email"] == "joey@redhat.com"
            assert last_row["suggested_value"] == "CRITICAL"
            assert last_row["submitted_value"] == "HIGH"
            # Non-matching values should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_exact_match(programmatic_feedback_log_setup):
    """
    Test programmatic feedback when suggested and submitted values match.
    Backend should calculate acceptance_score as 1.0.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "user@example.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "CRITICAL",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            last_row = rows[-1]
            assert last_row["suggested_value"] == "CRITICAL"
            assert last_row["submitted_value"] == "CRITICAL"
            # Exact match should result in acceptance_score of 1.0
            assert last_row["acceptance_score"] == "1.0"
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_empty_suggested_value(
    programmatic_feedback_log_setup,
):
    """
    Test programmatic feedback with empty suggested value.
    Backend should calculate acceptance_score as empty (None).
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-12345",
        "email": "user@example.com",
        "suggested_value": "",
        "submitted_value": "CWE-89",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0, "No rows found in programmatic feedback log"
            last_row = rows[-1]
            assert last_row["feature"] == "suggest-cwe"
            # Empty suggested value should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_empty_submitted_value(
    programmatic_feedback_log_setup,
):
    """
    Test programmatic feedback with empty submitted value.
    Backend should calculate acceptance_score as empty (None).
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-12345",
        "email": "user@example.com",
        "suggested_value": "CWE-79",
        "submitted_value": "",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0
            last_row = rows[-1]
            # Empty submitted value should result in empty acceptance_score
            assert last_row["acceptance_score"] == ""
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_validation_error_missing_feature():
    """
    Test request with missing required feature field.
    """
    feedback_data = {
        "cve_id": "CVE-2025-23395",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 422


def test_save_programmatic_feedback_rejects_acceptance_score_in_payload():
    """
    Test that sending acceptance_score in payload is rejected.
    The backend calculates acceptance_score server-side, so client-provided
    values should not be accepted.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
        "acceptance_score": 0.85,  # This should be rejected
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    # Request should be rejected with 422 Unprocessable Entity
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


def test_save_programmatic_feedback_rejects_llmjudge_explanation_in_payload():
    """
    Test that sending llmjudge_explanation in payload is rejected.
    The backend calculates llmjudge_explanation server-side via semantic scoring,
    so client-provided values should not be accepted.
    """
    feedback_data = {
        "feature": "suggest-title",
        "cve_id": "CVE-2025-23395",
        "suggested_value": "Buffer overflow vulnerability",
        "submitted_value": "Memory corruption issue",
        "llmjudge_explanation": "This should not be allowed",  # This should be rejected
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    # Request should be rejected with 422 Unprocessable Entity
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


def test_save_programmatic_feedback_allows_duplicate_submissions(
    programmatic_feedback_log_setup,
):
    """
    Test that duplicate programmatic feedback submissions are allowed at write time.
    Deduplication happens at KPI read time, not at write time.
    """
    feedback_data = {
        "feature": "suggest-cwe",
        "cve_id": "CVE-2025-14322",
        "email": "user@example.com",
        "suggested_value": "CWE-193",
        "submitted_value": "CWE-501",
    }

    # First submission should succeed
    response1 = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response1.status_code == 200

    # Second identical submission should also succeed (deduplication at read time)
    response2 = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response2.status_code == 200

    # Both entries are written to the log (deduplication happens at KPI read time)
    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            matching_rows = [
                r
                for r in rows
                if r["feature"] == "suggest-cwe"
                and r["cve_id"] == "CVE-2025-14322"
                and r["email"] == "user@example.com"
            ]
            assert len(matching_rows) == 2, "Expected two entries in log"
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


def test_save_programmatic_feedback_allows_different_submitted_value(
    programmatic_feedback_log_setup,
):
    """
    Test that submissions with different submitted_value are allowed (not duplicates).
    """
    base_feedback = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-99999",
        "email": "user@example.com",
        "suggested_value": "CRITICAL",
    }

    # First submission
    response1 = client.post(
        "/api/v1/programmatic-feedback",
        json={**base_feedback, "submitted_value": "HIGH"},
    )
    assert response1.status_code == 200

    # Second submission with different submitted_value should succeed
    response2 = client.post(
        "/api/v1/programmatic-feedback",
        json={**base_feedback, "submitted_value": "MODERATE"},
    )
    assert response2.status_code == 200


def test_save_programmatic_feedback_csv_schema_fields(programmatic_feedback_log_setup):
    """
    Test that CSV log has all expected schema fields.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "test@example.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }
    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)
    assert response.status_code == 200

    try:
        with open(
            programmatic_feedback_log_setup, "r", newline="", encoding="utf-8"
        ) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) > 0
            last_row = rows[-1]
            # Validate against schema fields
            expected_fields = set(PROGRAMMATIC_FEEDBACK_SCHEMA.field_names)
            assert set(last_row.keys()) == expected_fields, (
                "CSV row fields don't match schema"
            )
            # Check auto-populated fields
            assert last_row["datetime"] != ""  # Should be auto-populated
            assert last_row["version"] != ""  # Should be auto-populated
    except FileNotFoundError:
        pytest.fail(
            f"programmatic feedback log file was not created at: {programmatic_feedback_log_setup}"
        )


@pytest.mark.asyncio
async def test_semantic_scoring_success(programmatic_feedback_log_setup):
    """
    Test that process_semantic_scoring updates CSV when scoring succeeds.
    This tests the background task logic directly.
    """
    from aegis_ai_web.src.main import process_semantic_scoring
    from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

    # Create a CSV entry that semantic scoring will update
    entry_datetime = "2025-01-15 10:30:45.123"
    cve_id = "CVE-2025-23395"
    feature = "suggest-title"

    with open(programmatic_feedback_log_setup, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names)
        writer.writeheader()
        writer.writerow(
            {
                "datetime": entry_datetime,
                "feature": feature,
                "cve_id": cve_id,
                "email": "test@example.com",
                "suggested_value": "A vulnerability in the system",
                "submitted_value": "A security flaw in the system",
                "acceptance_score": "",
                "llmjudge_explanation": "",
                "version": "0.5.0",
            }
        )

    # Mock semantic scoring to return a tuple of (score, explanation)
    with patch(
        "aegis_ai_web.src.main.calculate_semantic_proximity_score",
        new_callable=AsyncMock,
        return_value=(0.75, "The texts are semantically similar"),
    ):
        # Call process_semantic_scoring directly
        result = await process_semantic_scoring(
            feature=feature,
            suggested="A vulnerability in the system",
            submitted="A security flaw in the system",
            cve_id=cve_id,
            entry_datetime=entry_datetime,
            email="test@example.com",
        )

    assert result == 0.75

    # Verify the score was updated in the CSV
    with open(programmatic_feedback_log_setup, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        last_row = rows[-1]
        assert last_row["acceptance_score"] == "0.75"


@pytest.mark.asyncio
async def test_semantic_scoring_failure_returns_none(programmatic_feedback_log_setup):
    """
    Test that when semantic scoring fails (returns None), the function returns None.
    The entry will remain with empty acceptance_score in the CSV.
    """
    from aegis_ai_web.src.main import process_semantic_scoring

    entry_datetime = "2025-01-15 10:30:45.123"
    cve_id = "CVE-2025-12345"
    feature = "suggest-description"

    # Mock semantic scoring to return (None, None) (failure)
    with patch(
        "aegis_ai_web.src.main.calculate_semantic_proximity_score",
        new_callable=AsyncMock,
        return_value=(None, None),
    ):
        result = await process_semantic_scoring(
            feature=feature,
            suggested="A description of the vulnerability",
            submitted="A different description",
            cve_id=cve_id,
            entry_datetime=entry_datetime,
            email="test@example.com",
        )

    assert result is None


@pytest.mark.asyncio
async def test_semantic_scoring_exception_returns_none(programmatic_feedback_log_setup):
    """
    Test that exceptions during semantic scoring are handled gracefully
    and return None. The entry will remain with empty acceptance_score.
    """
    from aegis_ai_web.src.main import process_semantic_scoring

    entry_datetime = "2025-01-15 10:30:45.123"
    cve_id = "CVE-2025-99999"
    feature = "suggest-statement"

    # Mock semantic scoring to raise an exception
    with patch(
        "aegis_ai_web.src.main.calculate_semantic_proximity_score",
        new_callable=AsyncMock,
        side_effect=Exception("LLM service unavailable"),
    ):
        result = await process_semantic_scoring(
            feature=feature,
            suggested="Statement text",
            submitted="Different statement text",
            cve_id=cve_id,
            entry_datetime=entry_datetime,
            email="test@example.com",
        )

    # Should return None (exception caught)
    assert result is None


def test_non_semantic_feature_uses_exact_match(programmatic_feedback_log_setup):
    """
    Test that non-semantic features (like suggest-impact) still use exact match.
    """
    feedback_data = {
        "feature": "suggest-impact",
        "cve_id": "CVE-2025-23395",
        "email": "user@example.com",
        "suggested_value": "CRITICAL",
        "submitted_value": "HIGH",
    }

    response = client.post("/api/v1/programmatic-feedback", json=feedback_data)

    assert response.status_code == 200

    # Verify exact match logic was used (empty score for non-match)
    with open(programmatic_feedback_log_setup, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        last_row = rows[-1]
        assert last_row["acceptance_score"] == ""  # Non-match = empty


class TestGetSemanticScoredFeatures:
    """Tests for get_semantic_scored_features function."""

    def test_includes_text_based_features(self):
        """Test that all text-based features are included."""
        from aegis_ai_web.src.semantic_scoring import get_semantic_scored_features

        features = get_semantic_scored_features()

        # Text-based features that use LLM judge
        assert "suggest-title" in features
        assert "suggest-description" in features
        assert "suggest-statement" in features
        assert "suggest-mitigation" in features

    def test_includes_structured_features(self):
        """Test that structured features (CWE, CVSS) are included."""
        from aegis_ai_web.src.semantic_scoring import get_semantic_scored_features

        features = get_semantic_scored_features()

        assert "suggest-cwe" in features
        assert "suggest-impact" in features
        assert "suggest-cvss" in features  # Alias for suggest-impact

    def test_returns_list(self):
        """Test that function returns a list."""
        from aegis_ai_web.src.semantic_scoring import get_semantic_scored_features

        features = get_semantic_scored_features()

        assert isinstance(features, list)
        assert len(features) >= 7  # At least the 7 known features


class TestParseJsonList:
    """Tests for _parse_json_list helper function."""

    def test_valid_json_array(self):
        """Test parsing valid JSON array."""
        from aegis_ai_web.src.semantic_scoring import _parse_json_list

        result = _parse_json_list('["CWE-79", "CWE-89"]')
        assert result == ["CWE-79", "CWE-89"]

    def test_empty_json_array(self):
        """Test parsing empty JSON array."""
        from aegis_ai_web.src.semantic_scoring import _parse_json_list

        result = _parse_json_list("[]")
        assert result == []

    def test_malformed_json(self):
        """Test that malformed JSON returns None."""
        from aegis_ai_web.src.semantic_scoring import _parse_json_list

        result = _parse_json_list("not-json")
        assert result is None

    def test_json_object_instead_of_array(self):
        """Test that JSON object returns None (not an array)."""
        from aegis_ai_web.src.semantic_scoring import _parse_json_list

        result = _parse_json_list('{"key": "value"}')
        assert result is None


class TestScoreCweLists:
    """Tests for _score_cwe_lists function."""

    def test_identical_lists(self):
        """Test scoring identical CWE lists."""
        from aegis_ai_web.src.semantic_scoring import _score_cwe_lists

        score = _score_cwe_lists(["CWE-79"], ["CWE-79"])
        assert score == 1.0

    def test_overlapping_lists(self):
        """Test scoring overlapping CWE lists."""
        from aegis_ai_web.src.semantic_scoring import _score_cwe_lists

        score = _score_cwe_lists(["CWE-79", "CWE-89"], ["CWE-79"])
        assert 0.0 < score < 1.0

    def test_disjoint_lists(self):
        """Test scoring disjoint CWE lists."""
        from aegis_ai_web.src.semantic_scoring import _score_cwe_lists

        score = _score_cwe_lists(["CWE-79"], ["CWE-89"])
        assert score == 0.0

    def test_empty_lists(self):
        """Test scoring empty CWE lists."""
        from aegis_ai_web.src.semantic_scoring import _score_cwe_lists

        score = _score_cwe_lists([], [])
        # Empty lists should return a valid score (implementation dependent)
        assert score is not None
        assert 0.0 <= score <= 1.0


class TestIsCvssVector:
    """Tests for _is_cvss_vector helper function."""

    def test_valid_cvss31_vector(self):
        """Test detection of valid CVSS 3.1 vector."""
        from aegis_ai_web.src.semantic_scoring import _is_cvss_vector

        assert _is_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is True

    def test_valid_cvss30_vector(self):
        """Test detection of valid CVSS 3.0 vector."""
        from aegis_ai_web.src.semantic_scoring import _is_cvss_vector

        assert _is_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is True

    def test_simple_severity_string(self):
        """Test that simple severity strings are not detected as CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import _is_cvss_vector

        assert _is_cvss_vector("CRITICAL") is False
        assert _is_cvss_vector("HIGH") is False
        assert _is_cvss_vector("MODERATE") is False
        assert _is_cvss_vector("LOW") is False

    def test_invalid_string(self):
        """Test that invalid strings are not detected as CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import _is_cvss_vector

        assert _is_cvss_vector("INVALID_VECTOR") is False
        assert _is_cvss_vector("") is False


class TestScoreCvssVectors:
    """Tests for _score_cvss_vectors function."""

    def test_identical_vectors(self):
        """Test scoring identical CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import _score_cvss_vectors

        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score, reason = _score_cvss_vectors(vector, vector)
        assert score == 1.0

    def test_different_vectors(self):
        """Test scoring different CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import _score_cvss_vectors

        suggested = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        submitted = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"  # UI:R instead of UI:N
        )
        score, reason = _score_cvss_vectors(suggested, submitted)
        # Should be a valid score less than 1.0
        assert score is not None
        assert 0.0 <= score < 1.0

    def test_non_cvss_vectors_returns_none(self):
        """Test that non-CVSS vectors return None."""
        from aegis_ai_web.src.semantic_scoring import _score_cvss_vectors

        score, reason = _score_cvss_vectors("CRITICAL", "HIGH")
        assert score is None
        assert reason is not None and "not CVSS vectors" in reason


@pytest.mark.asyncio
class TestScoreWithLlmJudge:
    """Tests for _score_with_llm_judge function.

    Note: _score_with_llm_judge raises exceptions (TimeoutError, etc.) rather than
    catching them. Exception handling is done at the calculate_semantic_proximity_score level.
    """

    @patch("aegis_ai_web.src.semantic_scoring.create_llm_judge")
    async def test_timeout_raises_timeout_error(self, mock_create_judge):
        """Test that timeout raises TimeoutError (handled by caller)."""
        from aegis_ai_web.src.semantic_scoring import _score_with_llm_judge

        # Mock the judge to take forever
        mock_judge = AsyncMock()

        async def slow_evaluate(*args, **kwargs):
            await asyncio.sleep(100)
            return 0.5

        mock_judge.evaluate = slow_evaluate
        mock_create_judge.return_value = mock_judge

        # Set a very short timeout
        import aegis_ai_web.src.semantic_scoring as ss

        original_timeout = ss.AEGIS_LLM_TIMEOUT_SECS
        ss.AEGIS_LLM_TIMEOUT_SECS = 1  # Very short timeout (1 second)
        try:
            with pytest.raises(TimeoutError):
                await _score_with_llm_judge("suggested", "submitted", "rubric")
        finally:
            ss.AEGIS_LLM_TIMEOUT_SECS = original_timeout

    @patch("aegis_ai_web.src.semantic_scoring.create_llm_judge")
    async def test_exception_propagates(self, mock_create_judge):
        """Test that exceptions propagate (handled by caller)."""
        from aegis_ai_web.src.semantic_scoring import _score_with_llm_judge

        # Mock the judge to raise an exception
        mock_judge = AsyncMock()
        mock_judge.evaluate.side_effect = Exception("LLM service error")
        mock_create_judge.return_value = mock_judge

        with pytest.raises(Exception, match="LLM service error"):
            await _score_with_llm_judge("suggested", "submitted", "rubric")

    @patch("aegis_ai_web.src.semantic_scoring.create_llm_judge")
    async def test_success_returns_score_from_dict(self, mock_create_judge):
        """Test that successful scoring extracts score from dict result."""
        from aegis_ai_web.src.semantic_scoring import _score_with_llm_judge
        from pydantic_evals.evaluators.evaluator import EvaluationReason

        # Mock the judge to return a dict with EvaluationReason (actual LLMJudge behavior)
        mock_judge = AsyncMock()
        mock_judge.evaluate.return_value = {
            "SemanticScoring": EvaluationReason(value=0.85, reason="Good match")
        }
        mock_create_judge.return_value = mock_judge

        result = await _score_with_llm_judge("suggested", "submitted", "rubric")
        assert result == (0.85, "Good match")

    @patch("aegis_ai_web.src.semantic_scoring.create_llm_judge")
    async def test_success_returns_score_from_float(self, mock_create_judge):
        """Test that successful scoring handles direct float result."""
        from aegis_ai_web.src.semantic_scoring import _score_with_llm_judge

        # Mock the judge to return a direct float (alternative LLMJudge behavior)
        mock_judge = AsyncMock()
        mock_judge.evaluate.return_value = 0.85
        mock_create_judge.return_value = mock_judge

        result = await _score_with_llm_judge("suggested", "submitted", "rubric")
        assert result == (0.85, None)


@pytest.mark.asyncio
class TestCalculateSemanticProximityScore:
    """Tests for calculate_semantic_proximity_score function."""

    async def test_empty_suggested_returns_none(self):
        """Test that empty suggested value returns None."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested="",
            submitted="some value",
            feature="suggest-title",
        )
        assert score is None

    async def test_empty_submitted_returns_none(self):
        """Test that empty submitted value returns None."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested="some value",
            submitted="",
            feature="suggest-title",
        )
        assert score is None

    async def test_unsupported_feature_returns_none(self):
        """Test that unsupported features return None."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested="value",
            submitted="value",
            feature="unsupported-feature",
        )
        assert score is None

    async def test_cwe_valid_json(self):
        """Test CWE scoring with valid JSON."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested='["CWE-79"]',
            submitted='["CWE-79"]',
            feature="suggest-cwe",
        )
        assert score == 1.0

    async def test_cwe_malformed_json(self):
        """Test CWE scoring with malformed JSON returns None."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested='["CWE-79"]',
            submitted="not-json",
            feature="suggest-cwe",
        )
        assert score is None

    async def test_impact_with_simple_strings(self):
        """Test that impact scoring with simple strings (not CVSS) returns None."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        # Simple severity strings are not CVSS vectors, should return None
        score, explanation = await calculate_semantic_proximity_score(
            suggested="CRITICAL",
            submitted="HIGH",
            feature="suggest-impact",
        )
        assert score is None

    async def test_impact_with_cvss_vectors(self):
        """Test impact scoring with valid CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        score, explanation = await calculate_semantic_proximity_score(
            suggested="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            submitted="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            feature="suggest-impact",
        )
        assert score == 1.0

    async def test_cvss_alias_with_cvss_vectors(self):
        """Test suggest-cvss (alias for suggest-impact) with CVSS vectors."""
        from aegis_ai_web.src.semantic_scoring import calculate_semantic_proximity_score

        # suggest-cvss should work the same as suggest-impact for CVSS vectors
        score, explanation = await calculate_semantic_proximity_score(
            suggested="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            submitted="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            feature="suggest-cvss",
            cve_id="CVE-2020-TEST",
        )
        # Different vectors should return a score < 1.0
        assert score is not None
        assert 0.0 < score < 1.0


class TestRetryUnscoredEntries:
    """Tests for the retry_failed_scoring.py script that queries CSV directly."""

    def test_get_unscored_entries(self, tmp_path, monkeypatch):
        """Test that get_unscored_entries finds entries with empty acceptance_score."""
        from scripts.retry_failed_scoring import get_unscored_entries
        from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

        csv_file = tmp_path / "programmatic_feedback.csv"
        monkeypatch.setenv("AEGIS_WEB_PROGRAMMATIC_FEEDBACK_LOG", str(csv_file))

        # Create CSV with mixed entries
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            # Entry with score (should be excluded)
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-title",
                    "cve_id": "CVE-2025-0001",
                    "email": "test@example.com",
                    "suggested_value": "title 1",
                    "submitted_value": "title 1",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            # Entry without score for semantic feature (should be included)
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:31:45.123",
                    "feature": "suggest-description",
                    "cve_id": "CVE-2025-0002",
                    "email": "test@example.com",
                    "suggested_value": "desc 1",
                    "submitted_value": "desc 2",
                    "acceptance_score": "",
                    "version": "0.5.0",
                }
            )
            # Entry without score for non-semantic feature (should be excluded)
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:32:45.123",
                    "feature": "suggest-unknown",
                    "cve_id": "CVE-2025-0003",
                    "email": "test@example.com",
                    "suggested_value": "val 1",
                    "submitted_value": "val 2",
                    "acceptance_score": "",
                    "version": "0.5.0",
                }
            )

        unscored = get_unscored_entries()
        assert len(unscored) == 1
        assert unscored[0]["cve_id"] == "CVE-2025-0002"
        assert unscored[0]["feature"] == "suggest-description"

    @pytest.mark.asyncio
    @patch(
        "scripts.retry_failed_scoring.calculate_semantic_proximity_score",
        new_callable=AsyncMock,
    )
    async def test_retry_entry_success(
        self, mock_semantic_score, tmp_path, monkeypatch
    ):
        """Test that retry_entry updates CSV on success."""
        from scripts.retry_failed_scoring import retry_entry
        from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

        csv_file = tmp_path / "programmatic_feedback.csv"
        monkeypatch.setenv("AEGIS_WEB_PROGRAMMATIC_FEEDBACK_LOG", str(csv_file))

        datetime_str = "2025-01-15 10:30:45.123"
        cve_id = "CVE-2025-0001"
        feature = "suggest-title"

        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": datetime_str,
                    "feature": feature,
                    "cve_id": cve_id,
                    "email": "test@example.com",
                    "suggested_value": "A vulnerability title",
                    "submitted_value": "A security flaw title",
                    "acceptance_score": "",
                    "llmjudge_explanation": "",
                    "version": "0.5.0",
                }
            )

        mock_semantic_score.return_value = (0.85, "Titles are semantically similar")

        entry = {
            "datetime": datetime_str,
            "cve_id": cve_id,
            "feature": feature,
            "suggested_value": "A vulnerability title",
            "submitted_value": "A security flaw title",
        }

        success = await retry_entry(entry, dry_run=False)
        assert success is True

        # Verify CSV was updated
        with open(csv_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert rows[0]["acceptance_score"] == "0.85"

    @pytest.mark.asyncio
    @patch(
        "scripts.retry_failed_scoring.calculate_semantic_proximity_score",
        new_callable=AsyncMock,
    )
    async def test_retry_entry_dry_run(
        self, mock_semantic_score, tmp_path, monkeypatch
    ):
        """Test that dry_run mode doesn't modify anything."""
        from scripts.retry_failed_scoring import retry_entry
        from aegis_ai_web.src.data_models import PROGRAMMATIC_FEEDBACK_SCHEMA

        csv_file = tmp_path / "programmatic_feedback.csv"
        monkeypatch.setenv("AEGIS_WEB_PROGRAMMATIC_FEEDBACK_LOG", str(csv_file))

        datetime_str = "2025-01-15 10:30:45.123"

        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": datetime_str,
                    "feature": "suggest-title",
                    "cve_id": "CVE-2025-0001",
                    "email": "test@example.com",
                    "suggested_value": "suggested",
                    "submitted_value": "submitted",
                    "acceptance_score": "",
                    "llmjudge_explanation": "",
                    "version": "0.5.0",
                }
            )

        mock_semantic_score.return_value = (0.85, "Similar texts")

        entry = {
            "datetime": datetime_str,
            "cve_id": "CVE-2025-0001",
            "feature": "suggest-title",
            "suggested_value": "suggested",
            "submitted_value": "submitted",
        }

        success = await retry_entry(entry, dry_run=True)
        assert success is True

        # Verify CSV was NOT updated (dry run)
        with open(csv_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert rows[0]["acceptance_score"] == ""
