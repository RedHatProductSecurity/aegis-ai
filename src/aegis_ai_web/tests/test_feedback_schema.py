#!/usr/bin/env python3
"""
Tests for feedback_schema.py

Run with: pytest src/aegis_ai_web/tests/test_feedback_schema.py -v
"""

import dataclasses
from typing import Dict, cast

import pytest

from aegis_ai_web.src.data_models import (
    FEEDBACK_SCHEMA,
    validate_log_parser_output,
    validate_csv_headers,
)


class TestFeedbackSchema:
    """Test cases for FeedbackSchema class."""

    def test_schema_fields_defined(self):
        """Test that schema has fields defined."""
        assert FEEDBACK_SCHEMA.FIELDS is not None
        assert len(FEEDBACK_SCHEMA.FIELDS) > 0

    def test_schema_field_names(self):
        """Test that schema contains expected fields."""
        expected_fields = [
            "datetime",
            "feature",
            "cve_id",
            "email",
            "actual",
            "expected",
            "request_time",
            "accept",
            "rejection_comment",
            "version",
        ]

        assert FEEDBACK_SCHEMA.field_names == expected_fields

    def test_csv_headers_match_fields(self):
        """Test that CSV headers match field names."""
        assert FEEDBACK_SCHEMA.csv_headers == FEEDBACK_SCHEMA.field_names

    def test_validate_parsed_log_valid(self):
        """Test validation of valid parsed log data."""
        valid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            "cve_id": "CVE-2025-23395",
            "email": "user@example.com",
            "actual": "IMPORTANT",
            "expected": "CRITICAL",
            "request_time": "",
            "accept": "False",
            "rejection_comment": "",
            "version": "1.0.0",
        }

        assert FEEDBACK_SCHEMA.validate_parsed_log(valid_data) is True

    def test_validate_parsed_log_missing_field(self):
        """Test validation fails with missing field."""
        invalid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            "cve_id": "CVE-2025-23395",
            # Missing: email, actual, expected, request_time, accept
        }

        assert FEEDBACK_SCHEMA.validate_parsed_log(invalid_data) is False

    def test_validate_parsed_log_extra_field(self):
        """Test validation fails with extra field."""
        invalid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            "cve_id": "CVE-2025-23395",
            "email": "user@example.com",
            "actual": "IMPORTANT",
            "expected": "CRITICAL",
            "request_time": "",
            "accept": "False",
            "rejection_comment": "",
            "version": "1.0.0",
            "extra_field": "should not be here",  # Extra field
        }

        assert FEEDBACK_SCHEMA.validate_parsed_log(invalid_data) is False

    def test_validate_parsed_log_none(self):
        """Test validation fails with None."""
        assert FEEDBACK_SCHEMA.validate_parsed_log(None) is False

    def test_validate_parsed_log_none_values(self):
        """Test validation fails when all keys are present but at least one value is None."""
        invalid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            "cve_id": "CVE-2025-23395",
            "email": None,  # None value
            "actual": "IMPORTANT",
            "expected": "CRITICAL",
            "request_time": "",
            "accept": "False",
            "rejection_comment": "",
            "version": "1.0.0",
        }

        # Cast to expected type for type checker; we're intentionally testing None values
        assert (
            FEEDBACK_SCHEMA.validate_parsed_log(cast(Dict[str, str], invalid_data))
            is False
        )

    def test_validate_csv_headers_valid(self):
        """Test validation of valid CSV headers."""
        valid_headers = [
            "datetime",
            "feature",
            "cve_id",
            "email",
            "actual",
            "expected",
            "request_time",
            "accept",
            "rejection_comment",
            "version",
        ]

        assert FEEDBACK_SCHEMA.validate_csv_headers(valid_headers) is True

    def test_validate_csv_headers_wrong_order(self):
        """Test validation fails with wrong field order."""
        invalid_headers = [
            "feature",  # Wrong order
            "datetime",
            "cve_id",
            "email",
            "actual",
            "expected",
            "request_time",
            "accept",
            "rejection_comment",
            "version",
        ]

        assert FEEDBACK_SCHEMA.validate_csv_headers(invalid_headers) is False

    def test_validate_csv_headers_missing_field(self):
        """Test validation fails with missing field."""
        invalid_headers = [
            "datetime",
            "feature",
            "cve_id",
            # Missing: email, actual, expected, request_time, accept
        ]

        assert FEEDBACK_SCHEMA.validate_csv_headers(invalid_headers) is False

    def test_get_field_description(self):
        """Test getting field descriptions."""
        desc = FEEDBACK_SCHEMA.get_field_description("datetime")
        assert desc is not None
        assert "millisecond" in desc.lower()

        desc = FEEDBACK_SCHEMA.get_field_description("feature")
        assert desc is not None

        desc = FEEDBACK_SCHEMA.get_field_description("nonexistent")
        assert desc is None


class TestValidationFunctions:
    """Test cases for validation convenience functions."""

    def test_validate_log_parser_output_valid(self):
        """Test validation function with valid data."""
        valid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            "cve_id": "CVE-2025-23395",
            "email": "user@example.com",
            "actual": "IMPORTANT",
            "expected": "CRITICAL",
            "request_time": "",
            "accept": "False",
            "rejection_comment": "",
            "version": "1.0.0",
        }

        assert validate_log_parser_output(valid_data) is True

    def test_validate_log_parser_output_invalid(self):
        """Test validation function raises with invalid data."""
        invalid_data = {
            "datetime": "2025-11-20 13:07:26.894",
            "feature": "suggest-impact",
            # Missing fields
        }

        with pytest.raises(AssertionError) as exc_info:
            validate_log_parser_output(invalid_data)

        assert "Missing fields" in str(exc_info.value)

    def test_validate_log_parser_output_none(self):
        """Test validation function raises with None."""
        with pytest.raises(AssertionError) as exc_info:
            validate_log_parser_output(None)

        assert "None" in str(exc_info.value)

    def test_validate_csv_headers_valid(self):
        """Test CSV header validation function with valid headers."""
        valid_headers = [
            "datetime",
            "feature",
            "cve_id",
            "email",
            "actual",
            "expected",
            "request_time",
            "accept",
            "rejection_comment",
            "version",
        ]

        assert validate_csv_headers(valid_headers) is True

    def test_validate_csv_headers_invalid(self):
        """Test CSV header validation function raises with invalid headers."""
        invalid_headers = ["wrong", "headers"]

        with pytest.raises(AssertionError) as exc_info:
            validate_csv_headers(invalid_headers)

        assert "do not match schema" in str(exc_info.value)


class TestSchemaIntegration:
    """Integration tests ensuring schema is used correctly."""

    def test_schema_consistency(self):
        """Test that schema is consistent across different access methods."""
        # All these should return the same list
        fields1 = FEEDBACK_SCHEMA.field_names
        fields2 = FEEDBACK_SCHEMA.csv_headers
        fields3 = FEEDBACK_SCHEMA.FIELDS

        assert fields1 == fields2 == fields3

    def test_schema_immutable(self):
        """Test that schema fields cannot be modified."""
        original_fields = FEEDBACK_SCHEMA.field_names.copy()

        # Schema is frozen, so this should raise FrozenInstanceError (a subclass of AttributeError)
        with pytest.raises(dataclasses.FrozenInstanceError):
            FEEDBACK_SCHEMA.FIELDS = ["new", "fields"]  # type: ignore[misc]

        # Verify fields unchanged
        assert FEEDBACK_SCHEMA.field_names == original_fields

    def test_all_fields_have_descriptions(self):
        """Test that all schema fields have descriptions."""
        for field in FEEDBACK_SCHEMA.field_names:
            desc = FEEDBACK_SCHEMA.get_field_description(field)
            assert desc is not None, f"Field '{field}' missing description"
            assert len(desc) > 0, f"Field '{field}' has empty description"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
