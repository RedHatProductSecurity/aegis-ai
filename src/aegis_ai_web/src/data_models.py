"""
Feedback-related data models and schemas for Aegis Web API.

This module contains all data models and schemas related to the feedback feature,
including the Pydantic model for API requests and the canonical schema for logging.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional

from pydantic import BaseModel, Field

from aegis_ai.data_models import CVEID


class Feedback(BaseModel):
    """
    Data structure for feedback.

    All fields are stored without modification to preserve original data.
    CSV escaping is handled automatically by the csv library during logging.
    """

    feature: str = Field(..., max_length=100)
    cve_id: Optional[CVEID] = Field("", max_length=50)
    email: Optional[str] = Field("", max_length=100)
    request_time: Optional[str] = Field("", max_length=50)
    actual: Optional[str] = Field("", max_length=5000)  # Increased for longer values
    expected: Optional[str] = Field("", max_length=5000)  # Increased for longer values
    accept: bool = Field(False)
    rejection_comment: Optional[str] = Field("", max_length=5000)


@dataclass(frozen=True)
class FeedbackSchema:
    """
    Canonical schema for feedback log entries.

    This schema defines the exact fields and their order for both:
    - Pipe-delimited log format
    - CSV export format

    All fields must be present in both formats in the same order.
    """

    # Field names in order - set in __post_init__
    FIELDS: List[str] = field(init=False)

    def __post_init__(self):
        # Use object.__setattr__ to set frozen dataclass field
        object.__setattr__(
            self,
            "FIELDS",
            [
                "datetime",  # Timestamp with millisecond precision
                "feature",  # Feature name (e.g., suggest-impact)
                "cve_id",  # CVE identifier
                "email",  # User email address
                "actual",  # Actual value from system
                "expected",  # Expected value from user
                "request_time",  # Original request timestamp
                "accept",  # User acceptance (True/False)
                "rejection_comment",  # Comment provided when rejecting the result
                "version",  # AEGIS version at time of feedback
            ],
        )

    @property
    def field_names(self) -> List[str]:
        """Get list of field names in order."""
        return self.FIELDS

    @property
    def csv_headers(self) -> List[str]:
        """Get CSV header names (same as field names)."""
        return self.FIELDS

    def validate_parsed_log(self, parsed_data: Optional[Dict[str, str]]) -> bool:
        """
        Validate that parsed log data contains exactly the schema fields with non-None values.

        Args:
            parsed_data: Dictionary from parse_log_line()

        Returns:
            True if valid, False otherwise
        """
        if parsed_data is None:
            return False

        parsed_fields = set(parsed_data.keys())
        schema_fields = set(self.FIELDS)

        # Check field names match
        if parsed_fields != schema_fields:
            return False

        # Check that all values are strings (not None)
        # CSV reader returns None for missing columns
        return all(v is not None for v in parsed_data.values())

    def validate_csv_headers(self, csv_headers: List[str]) -> bool:
        """
        Validate that CSV headers match the schema exactly.

        Args:
            csv_headers: List of CSV header names

        Returns:
            True if valid, False otherwise
        """
        return csv_headers == self.FIELDS

    def get_field_description(self, field_name: str) -> Optional[str]:
        """
        Get description for a field.

        Args:
            field_name: Name of the field

        Returns:
            Description string or None if field not found
        """
        descriptions = {
            "datetime": "Timestamp with millisecond precision (YYYY-MM-DD HH:MM:SS.mmm)",
            "feature": "Feature name (e.g., suggest-impact, suggest-cwe)",
            "cve_id": "CVE identifier (e.g., CVE-2025-23395)",
            "email": "User email address",
            "actual": "Actual value returned by the system",
            "expected": "Expected value provided by the user",
            "request_time": "Timestamp of the original request",
            "accept": "Whether the user accepted the result (True/False)",
            "rejection_comment": "Comment provided by the user when rejecting the result",
            "version": "AEGIS version at time of feedback submission",
        }
        return descriptions.get(field_name)


# Singleton instance
FEEDBACK_SCHEMA = FeedbackSchema()


def validate_log_parser_output(parsed_data: Optional[Dict[str, str]]) -> bool:
    """
    Convenience function to validate parsed log data.

    Args:
        parsed_data: Dictionary from parse_log_line()

    Returns:
        True if valid, raises AssertionError otherwise
    """
    is_valid = FEEDBACK_SCHEMA.validate_parsed_log(parsed_data)

    if not is_valid:
        if parsed_data is None:
            raise AssertionError("Parsed data is None")

        parsed_fields = set(parsed_data.keys())
        schema_fields = set(FEEDBACK_SCHEMA.FIELDS)

        missing = schema_fields - parsed_fields
        extra = parsed_fields - schema_fields

        error_msg = []
        if missing:
            error_msg.append(f"Missing fields: {sorted(missing)}")
        if extra:
            error_msg.append(f"Extra fields: {sorted(extra)}")

        raise AssertionError(
            f"Parsed log data does not match schema. {' '.join(error_msg)}"
        )

    return True


def validate_csv_headers(csv_headers: List[str]) -> bool:
    """
    Convenience function to validate CSV headers.

    Args:
        csv_headers: List of CSV header names

    Returns:
        True if valid, raises AssertionError otherwise
    """
    is_valid = FEEDBACK_SCHEMA.validate_csv_headers(csv_headers)

    if not is_valid:
        raise AssertionError(
            f"CSV headers {csv_headers} do not match schema {FEEDBACK_SCHEMA.FIELDS}"
        )

    return True


class KPIEntry(BaseModel):
    """
    Individual KPI entry model.

    Contains datetime, acceptance status, and AEGIS version for a feedback entry.
    """

    datetime: str = Field(
        ...,
        description="Timestamp of the feedback entry (format: YYYY-MM-DD HH:MM:SS.mmm or YYYY-MM-DD HH:MM:SS)",
    )
    accepted: bool = Field(..., description="Whether the feedback was accepted")
    aegis_version: str = Field(
        default="",
        description="AEGIS version at time of feedback (may be empty string if not available)",
    )


class FeatureKPI(BaseModel):
    """
    Feature KPI model for CVE analysis feedback.

    Contains the acceptance score percentage and filtered log entries for a feature.
    """

    acceptance_percentage: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Acceptance score as a percentage (0.0 to 100.0, e.g., 75.0 for 75%)",
    )
    entries: List[KPIEntry] = Field(
        ...,
        description="List of log entries filtered by feature, sorted by datetime",
    )
