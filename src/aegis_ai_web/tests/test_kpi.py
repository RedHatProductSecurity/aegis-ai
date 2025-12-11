"""
Tests for KPI endpoint module.
"""

import csv
from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app
from aegis_ai_web.src.feedback_logger import AegisLogger
from aegis_ai_web.src.data_models import FEEDBACK_SCHEMA

client = TestClient(app)


class TestReadFeedbackLogs:
    """Test cases for AegisLogger.read() method."""

    def test_read_feedback_logs_empty_file(self, feedback_log_setup):
        """Test reading from non-existent file returns empty list."""
        # File doesn't exist yet
        entries = AegisLogger.read()
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

        entries = AegisLogger.read()
        assert len(entries) == 2
        assert entries[0]["feature"] == "suggest-impact"
        assert entries[1]["feature"] == "suggest-cwe"
        # Ensure accept field is normalized to lowercase by AegisLogger.read()
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

        entries = AegisLogger.read()
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
