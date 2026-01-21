"""
Tests for KPI endpoint module.
"""

import csv
from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app
from aegis_ai_web.src.feedback_logger import feedback_logger
from aegis_ai_web.src.data_models import FEEDBACK_SCHEMA, PROGRAMMATIC_FEEDBACK_SCHEMA

client = TestClient(app)


class TestReadFeedbackLogs:
    """Test cases for feedback_logger.read() method."""

    def test_read_feedback_logs_empty_file(self, feedback_log_setup):
        """Test reading from non-existent file returns empty list."""
        # File doesn't exist yet
        entries = feedback_logger.read()
        assert entries == []

    def test_read_feedback_logs_valid_entries(self, feedback_log_setup):
        """Test reading valid log entries from CSV."""
        # Create test CSV with valid entries
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "CRITICAL",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:00:00.456",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23396",
                    "email": "test2@example.com",
                    "actual": "CWE-120",
                    "expected": "CWE-79",
                    "request_time": "2025-01-15 11:00:00",
                    "accept": "False",
                    "rejection_comment": "Wrong CWE",
                }
            )

        entries = feedback_logger.read()
        assert len(entries) == 2
        assert entries[0]["feature"] == "suggest-impact"
        assert entries[1]["feature"] == "suggest-cwe"
        # Ensure accept field is normalized to lowercase by feedback_logger.read()
        assert entries[0]["accept"] == "true"
        assert entries[1]["accept"] == "false"

    def test_read_feedback_logs_invalid_entries_filtered(self, feedback_log_setup):
        """Test that invalid entries are filtered out."""
        # Create CSV with one valid and one invalid entry
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Valid entry
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "CRITICAL",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            # Invalid entry - manually write a malformed line with missing fields
            # This will cause DictReader to return None for missing columns
            f.write("2025-01-15 11:00:00.456,suggest-cwe\n")

        entries = feedback_logger.read()
        assert len(entries) == 1
        assert entries[0]["feature"] == "suggest-impact"


class TestGetCveKpi:
    """Test cases for get_cve_kpi() endpoint function."""

    def test_get_cve_kpi_no_entries(self, feedback_log_setup):
        """Test KPI endpoint with no entries for feature."""
        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        assert data["suggest-impact"]["acceptance_percentage"] == 0.0
        assert data["suggest-impact"]["entries"] == []

    def test_get_cve_kpi_filter_by_feature(self, feedback_log_setup):
        """Test KPI endpoint filters entries by feature."""
        # Create test CSV with entries for different features
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Entry for suggest-impact
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "CRITICAL",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            # Entry for suggest-cwe (should be filtered out)
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:00:00.456",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23396",
                    "email": "test2@example.com",
                    "actual": "CWE-120",
                    "expected": "CWE-79",
                    "request_time": "2025-01-15 11:00:00",
                    "accept": "False",
                    "rejection_comment": "",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 1
        # Verify datetime, accepted, and aegis_version fields are included
        assert "datetime" in feature_data["entries"][0]
        assert "accepted" in feature_data["entries"][0]
        assert "aegis_version" in feature_data["entries"][0]
        assert feature_data["entries"][0]["datetime"] == "2025-01-15 10:30:45.123"
        # Verify accepted field is converted to boolean
        assert feature_data["entries"][0]["accepted"] is True
        assert isinstance(feature_data["entries"][0]["accepted"], bool)
        # Verify all three fields are present
        assert len(feature_data["entries"][0]) == 3
        # Verify score only includes entries for the requested feature
        assert feature_data["acceptance_percentage"] == 100.0

    def test_get_cve_kpi_score_calculation_all_accepted(self, feedback_log_setup):
        """Test KPI score calculation when all entries are accepted."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            for i in range(5):
                writer.writerow(
                    {
                        "datetime": f"2025-01-15 10:30:{i:02d}.123",
                        "feature": "suggest-impact",
                        "cve_id": f"CVE-2025-2339{i}",
                        "email": "test@example.com",
                        "actual": "IMPORTANT",
                        "expected": "",
                        "request_time": f"2025-01-15 10:30:{i:02d}",
                        "accept": "True",
                        "rejection_comment": "",
                    }
                )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert feature_data["acceptance_percentage"] == 100.0
        assert len(feature_data["entries"]) == 5

    def test_get_cve_kpi_score_calculation_mixed_acceptance(self, feedback_log_setup):
        """Test KPI score calculation with mixed acceptance values."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # 3 accepted, 2 rejected
            for i in range(3):
                writer.writerow(
                    {
                        "datetime": f"2025-01-15 10:30:{i:02d}.123",
                        "feature": "suggest-impact",
                        "cve_id": f"CVE-2025-2339{i}",
                        "email": "test@example.com",
                        "actual": "IMPORTANT",
                        "expected": "",
                        "request_time": f"2025-01-15 10:30:{i:02d}",
                        "accept": "True",
                        "rejection_comment": "",
                    }
                )
            for i in range(3, 5):
                writer.writerow(
                    {
                        "datetime": f"2025-01-15 10:30:{i:02d}.123",
                        "feature": "suggest-impact",
                        "cve_id": f"CVE-2025-2339{i}",
                        "email": "test@example.com",
                        "actual": "IMPORTANT",
                        "expected": "CRITICAL",
                        "request_time": f"2025-01-15 10:30:{i:02d}",
                        "accept": "False",
                        "rejection_comment": "Wrong impact",
                    }
                )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert feature_data["acceptance_percentage"] == 60.0  # 3/5 = 60%
        assert len(feature_data["entries"]) == 5
        # Verify accepted fields are converted to booleans
        assert feature_data["entries"][0]["accepted"] is True
        assert feature_data["entries"][3]["accepted"] is False
        assert all(
            isinstance(entry["accepted"], bool) for entry in feature_data["entries"]
        )

    def test_get_cve_kpi_score_calculation_lowercase_true(self, feedback_log_setup):
        """Test KPI score calculation accepts lowercase 'true'."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "true",  # lowercase
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:31:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:31:00",
                    "accept": "False",
                    "rejection_comment": "",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert feature_data["acceptance_percentage"] == 50.0  # 1/2 = 50%

    def test_get_cve_kpi_sorting_ascending(self, feedback_log_setup):
        """Test KPI endpoint sorts entries ascending by datetime."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Write entries in reverse chronological order
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:35:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )

        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=asc"
        )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        # Should be sorted ascending (oldest first)
        assert feature_data["entries"][0]["datetime"] == "2025-01-15 10:30:45.123"
        assert feature_data["entries"][1]["datetime"] == "2025-01-15 10:35:45.123"
        # Verify datetime, accepted, and aegis_version fields are present
        assert len(feature_data["entries"][0]) == 3
        assert "datetime" in feature_data["entries"][0]
        assert "accepted" in feature_data["entries"][0]
        assert "aegis_version" in feature_data["entries"][0]

    def test_get_cve_kpi_sorting_descending(self, feedback_log_setup):
        """Test KPI endpoint sorts entries descending by datetime."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Write entries in chronological order
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:35:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )

        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=desc"
        )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        # Should be sorted descending (newest first)
        assert feature_data["entries"][0]["datetime"] == "2025-01-15 10:35:45.123"
        assert feature_data["entries"][1]["datetime"] == "2025-01-15 10:30:45.123"
        # Verify datetime, accepted, and aegis_version fields are present
        assert len(feature_data["entries"][0]) == 3

    def test_get_cve_kpi_sorting_without_milliseconds(self, feedback_log_setup):
        """Test KPI endpoint handles datetime without milliseconds."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:45",  # No milliseconds
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:35:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",  # With milliseconds
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )

        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=asc"
        )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        # Should be sorted correctly despite different datetime formats
        assert (
            feature_data["entries"][0]["datetime"] == "2025-01-15 10:30:45.123"
        )  # Older entry first
        assert (
            feature_data["entries"][1]["datetime"] == "2025-01-15 10:35:45"
        )  # Newer entry second

    def test_get_cve_kpi_sorting_unparsable_datetime(self, feedback_log_setup):
        """Test KPI endpoint handles unparsable datetime values with fallback sorting."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "not-a-date",  # Invalid datetime
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "true",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",  # Valid datetime
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "true",
                    "rejection_comment": "",
                }
            )

        # Test ascending order - invalid datetime should be first (epoch)
        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=asc"
        )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        assert (
            feature_data["entries"][0]["datetime"] == "not-a-date"
        )  # Invalid datetime first (epoch)
        assert (
            feature_data["entries"][1]["datetime"] == "2025-01-15 10:30:45.123"
        )  # Valid datetime second

        # Test descending order - invalid datetime should be last
        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=desc"
        )
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        assert (
            feature_data["entries"][0]["datetime"] == "2025-01-15 10:30:45.123"
        )  # Valid datetime first
        assert (
            feature_data["entries"][1]["datetime"] == "not-a-date"
        )  # Invalid datetime last (epoch)

    def test_get_cve_kpi_missing_feature_parameter(self, feedback_log_setup):
        """Test KPI endpoint rejects requests without required feature parameter."""
        response = client.get("/api/v1/analysis/kpi/cve")
        assert response.status_code == 422
        error_detail = response.json()["detail"]
        # Check that the error mentions the missing feature parameter
        assert any(
            "feature" in str(err).lower()
            and ("missing" in str(err).lower() or "required" in str(err).lower())
            for err in error_detail
        )

    def test_get_cve_kpi_invalid_order_parameter(self, feedback_log_setup):
        """Test KPI endpoint rejects invalid order parameter."""
        response = client.get(
            "/api/v1/analysis/kpi/cve?feature=suggest-impact&order=invalid"
        )
        assert response.status_code == 422
        # FastAPI validation returns a list of validation errors
        error_detail = response.json()["detail"]
        # Check that the error mentions the order parameter
        assert any("order" in str(err).lower() for err in error_detail)

    def test_get_cve_kpi_default_order_ascending(self, feedback_log_setup):
        """Test KPI endpoint defaults to ascending order."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:35:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )

        # Don't specify order parameter - should default to asc
        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert len(feature_data["entries"]) == 2
        # Should be sorted ascending (oldest first) by default
        assert feature_data["entries"][0]["datetime"] == "2025-01-15 10:30:45.123"
        assert feature_data["entries"][1]["datetime"] == "2025-01-15 10:35:45.123"

    def test_get_cve_kpi_score_rounding(self, feedback_log_setup):
        """Test KPI score rounding (e.g., 33.33% rounds to 33%)."""
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # 1 accepted out of 3 = 33.33%, should round to 33%
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            for i in range(2):
                writer.writerow(
                    {
                        "datetime": f"2025-01-15 10:31:{i:02d}.123",
                        "feature": "suggest-impact",
                        "cve_id": f"CVE-2025-2339{i + 6}",
                        "email": "test@example.com",
                        "actual": "IMPORTANT",
                        "expected": "",
                        "request_time": f"2025-01-15 10:31:{i:02d}",
                        "accept": "False",
                        "rejection_comment": "",
                    }
                )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]
        assert (
            feature_data["acceptance_percentage"] == 33.3
        )  # 1/3 = 33.33% rounded to 33.3

    def test_get_cve_kpi_all_features(self, feedback_log_setup):
        """Test KPI endpoint with feature='all' returns dict with all features."""
        # Create test CSV with entries for multiple features
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Entry for suggest-impact
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                }
            )
            # Entry for suggest-cwe
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:00:00.456",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23396",
                    "email": "test2@example.com",
                    "actual": "CWE-120",
                    "expected": "",
                    "request_time": "2025-01-15 11:00:00",
                    "accept": "False",
                    "rejection_comment": "",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=all")
        assert response.status_code == 200
        data = response.json()
        # Should return a dict with all features
        assert isinstance(data, dict)
        assert "suggest-impact" in data
        assert "suggest-cwe" in data
        # Verify each feature has the expected structure
        assert "acceptance_percentage" in data["suggest-impact"]
        assert "entries" in data["suggest-impact"]
        assert "acceptance_percentage" in data["suggest-cwe"]
        assert "entries" in data["suggest-cwe"]
        # Verify scores
        assert data["suggest-impact"]["acceptance_percentage"] == 100.0
        assert data["suggest-cwe"]["acceptance_percentage"] == 0.0

    def test_get_cve_kpi_includes_programmatic_entries(
        self, feedback_log_setup, programmatic_feedback_log_setup
    ):
        """Test KPI endpoint folds programmatic entries into the entries list."""
        # Create standard feedback
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )

        # Create programmatic feedback with acceptance scores
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            # Exact match (score 1.0) -> accepted=True
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:00.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "user@example.com",
                    "suggested_value": "CRITICAL",
                    "submitted_value": "CRITICAL",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            # Another exact match (score 1.0) -> accepted=True
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:40:00.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23397",
                    "email": "user@example.com",
                    "suggested_value": "HIGH",
                    "submitted_value": "HIGH",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            # Partially accepted programmatic entry (score 0.4) -> accepted=False
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:45:00.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23398",
                    "email": "user@example.com",
                    "suggested_value": "MODERATE",
                    "submitted_value": "LOW",
                    "acceptance_score": "0.4",
                    "version": "0.5.0",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        assert "suggest-impact" in data
        feature_data = data["suggest-impact"]

        # 1 standard + 3 programmatic entries = 4 total
        assert len(feature_data["entries"]) == 4

        # Verify the partially accepted entry appears with accepted=False
        # Find entry by datetime since KPIEntry doesn't include cve_id or source
        partial_entry = next(
            (
                e
                for e in feature_data["entries"]
                if e.get("datetime") == "2025-01-15 10:45:00.123"
            ),
            None,
        )
        assert partial_entry is not None, (
            "Partially accepted programmatic entry should be present"
        )
        # The entry should have accepted=False since score is 0.4 != 1.0
        assert partial_entry.get("accepted") is False

        # Acceptance percentage: 1 standard (True) + 2 programmatic (1.0) + 1 programmatic (0.4=False) = 3/4 = 75.0%
        assert feature_data["acceptance_percentage"] == 75.0

    def test_get_cve_kpi_programmatic_excludes_empty_scores(
        self, feedback_log_setup, programmatic_feedback_log_setup
    ):
        """Test KPI entries only include programmatic entries with non-empty acceptance scores."""
        # Create standard feedback
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "CWE-79",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )

        # Create programmatic feedback - mix of scored and unscored
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            # Exact match (score 1.0) -> included
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23396",
                    "email": "user@example.com",
                    "suggested_value": "CWE-79",
                    "submitted_value": "CWE-79",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            # No match - empty score (should be excluded)
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:40:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23397",
                    "email": "user@example.com",
                    "suggested_value": "CWE-79",
                    "submitted_value": "CWE-89",
                    "acceptance_score": "",  # Empty score - excluded
                    "version": "0.5.0",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-cwe")
        assert response.status_code == 200
        data = response.json()
        feature_data = data["suggest-cwe"]

        # 1 standard + 1 programmatic (empty score excluded) = 2 total
        assert len(feature_data["entries"]) == 2
        assert feature_data["acceptance_percentage"] == 100.0

    def test_get_cve_kpi_standard_only_no_programmatic(
        self, feedback_log_setup, programmatic_feedback_log_setup
    ):
        """Test KPI endpoint when no programmatic feedback exists for feature."""
        # Create standard feedback only
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-impact")
        assert response.status_code == 200
        data = response.json()
        feature_data = data["suggest-impact"]

        # Only standard feedback entries
        assert len(feature_data["entries"]) == 1
        assert feature_data["acceptance_percentage"] == 100.0

    def test_get_cve_kpi_all_combines_entries(
        self, feedback_log_setup, programmatic_feedback_log_setup
    ):
        """Test KPI endpoint with feature='all' combines standard and programmatic entries."""
        # Create standard feedback
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23395",
                    "email": "test@example.com",
                    "actual": "IMPORTANT",
                    "expected": "",
                    "request_time": "2025-01-15 10:30:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )

        # Create programmatic feedback for multiple features
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:35:00.123",
                    "feature": "suggest-impact",
                    "cve_id": "CVE-2025-23396",
                    "email": "user@example.com",
                    "suggested_value": "CRITICAL",
                    "submitted_value": "CRITICAL",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:40:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-23397",
                    "email": "user@example.com",
                    "suggested_value": "CWE-79",
                    "submitted_value": "CWE-79",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )

        response = client.get("/api/v1/analysis/kpi/cve?feature=all")
        assert response.status_code == 200
        data = response.json()

        # Both features should be present
        assert "suggest-impact" in data
        assert "suggest-cwe" in data

        # suggest-impact: 1 standard + 1 programmatic = 2 entries
        assert len(data["suggest-impact"]["entries"]) == 2
        assert data["suggest-impact"]["acceptance_percentage"] == 100.0

        # suggest-cwe: 0 standard + 1 programmatic = 1 entry
        assert len(data["suggest-cwe"]["entries"]) == 1
        assert data["suggest-cwe"]["acceptance_percentage"] == 100.0

    def test_get_cve_kpi_all_deduplicates_programmatic_feedback(
        self,
        programmatic_feedback_log_setup,
    ):
        """Programmatic feedback is deduplicated by (cve_id, feature) keeping the latest entry only."""
        # Arrange: create two programmatic feedback rows for the same (cve_id, feature)
        cve_id = "CVE-2025-0001"
        feature = "suggest-impact"

        # Earlier entry, lower score
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names,
            )
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:30:45.123",
                    "cve_id": cve_id,
                    "feature": feature,
                    "email": "user@example.com",
                    "suggested_value": "CRITICAL",
                    "submitted_value": "HIGH",
                    "acceptance_score": "0.0",
                    "version": "0.5.0",
                }
            )
            # Later entry, higher score
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:30:45.123",
                    "cve_id": cve_id,
                    "feature": feature,
                    "email": "user@example.com",
                    "suggested_value": "CRITICAL",
                    "submitted_value": "CRITICAL",
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )

        # Act: call KPI endpoint for all features
        response = client.get("/api/v1/analysis/kpi/cve?feature=all")
        assert response.status_code == 200
        data = response.json()

        # Assert: only one programmatic entry is used for (cve_id, feature)
        assert feature in data
        feature_data = data[feature]

        # Exactly one deduplicated entry for this CVE/feature pair
        assert len(feature_data["entries"]) == 1

        # The kept entry must correspond to the later datetime
        kept_entry = feature_data["entries"][0]
        assert kept_entry["datetime"] == "2025-01-15 11:30:45.123"

        # And the acceptance_percentage should reflect the later score (1.0 = 100%)
        assert feature_data["acceptance_percentage"] == 100.0
        assert kept_entry["accepted"] is True

    def test_get_cve_kpi_mixed_standard_and_programmatic_feedback(
        self,
        feedback_log_setup,
        programmatic_feedback_log_setup,
    ):
        """
        Test KPI behavior when both standard and programmatic feedback exist for
        different (cve_id, feature) pairs.

        Standard feedback uses accept=true/false, programmatic uses acceptance_score.
        Both should be counted independently for different CVE IDs.
        """
        # Arrange: Create standard feedback for one CVE
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            # Standard feedback: accepted
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:00:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-0001",
                    "email": "user@example.com",
                    "actual": "CWE-79",
                    "expected": "",
                    "request_time": "2025-01-15 10:00:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )
            # Standard feedback: rejected
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:05:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-0002",
                    "email": "user@example.com",
                    "actual": "CWE-89",
                    "expected": "CWE-79",
                    "request_time": "2025-01-15 10:05:00",
                    "accept": "False",
                    "rejection_comment": "Wrong CWE",
                    "version": "0.5.0",
                }
            )

        # Arrange: Create programmatic feedback for a different CVE
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            # Programmatic feedback: high score (accepted)
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:00:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-0003",
                    "email": "user@example.com",
                    "suggested_value": '["CWE-79"]',
                    "submitted_value": '["CWE-79"]',
                    "acceptance_score": "1.0",
                    "version": "0.5.0",
                }
            )
            # Programmatic feedback: low score (rejected, score < 0.5)
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:05:00.123",
                    "feature": "suggest-cwe",
                    "cve_id": "CVE-2025-0004",
                    "email": "user@example.com",
                    "suggested_value": '["CWE-79"]',
                    "submitted_value": '["CWE-89"]',
                    "acceptance_score": "0.3",
                    "version": "0.5.0",
                }
            )

        # Act: Get KPI for the feature
        response = client.get("/api/v1/analysis/kpi/cve?feature=suggest-cwe")
        assert response.status_code == 200
        data = response.json()

        # Assert: Should have all 4 entries
        assert "suggest-cwe" in data
        feature_data = data["suggest-cwe"]
        assert len(feature_data["entries"]) == 4

        # Acceptance percentage: 2 accepted (1 standard, 1 programmatic) out of 4 = 50%
        # Standard: 1 accepted, 1 rejected
        # Programmatic: 1 accepted (1.0), 1 rejected (0.3)
        assert feature_data["acceptance_percentage"] == 50.0

    def test_get_cve_kpi_mixed_feedback_same_cve_different_entries(
        self,
        feedback_log_setup,
        programmatic_feedback_log_setup,
    ):
        """
        Test that standard and programmatic feedback for the SAME (cve_id, feature)
        are both counted as separate entries since they represent different feedback
        events (standard is explicit accept/reject, programmatic is suggestion comparison).
        """
        cve_id = "CVE-2025-0001"
        feature = "suggest-cwe"

        # Arrange: Create standard feedback
        with open(feedback_log_setup, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_SCHEMA.field_names)
            writer.writeheader()
            writer.writerow(
                {
                    "datetime": "2025-01-15 10:00:00.123",
                    "feature": feature,
                    "cve_id": cve_id,
                    "email": "user@example.com",
                    "actual": "CWE-79",
                    "expected": "",
                    "request_time": "2025-01-15 10:00:00",
                    "accept": "True",
                    "rejection_comment": "",
                    "version": "0.5.0",
                }
            )

        # Arrange: Create programmatic feedback for the same CVE
        with open(
            programmatic_feedback_log_setup, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.DictWriter(
                f, fieldnames=PROGRAMMATIC_FEEDBACK_SCHEMA.field_names
            )
            writer.writeheader()
            # Later programmatic entry with score < 0.5 (rejected)
            writer.writerow(
                {
                    "datetime": "2025-01-15 11:00:00.123",
                    "feature": feature,
                    "cve_id": cve_id,
                    "email": "user@example.com",
                    "suggested_value": '["CWE-79"]',
                    "submitted_value": '["CWE-89"]',
                    "acceptance_score": "0.2",
                    "version": "0.5.0",
                }
            )

        # Act: Get KPI
        response = client.get(f"/api/v1/analysis/kpi/cve?feature={feature}")
        assert response.status_code == 200
        data = response.json()

        # Assert: Both entries should be present (standard and programmatic are
        # different types of feedback events)
        assert feature in data
        feature_data = data[feature]
        assert len(feature_data["entries"]) == 2

        # Acceptance percentage: 1 accepted (standard), 1 rejected (programmatic) = 50%
        assert feature_data["acceptance_percentage"] == 50.0
