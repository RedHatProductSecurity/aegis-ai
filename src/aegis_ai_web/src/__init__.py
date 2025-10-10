# REST API
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from aegis_ai import config_dir
from aegis_ai.data_models import CVEID

AEGIS_REST_API_VERSION: str = "v1"

feature_agent = os.getenv("AEGIS_WEB_FEATURE_AGENT", "public")
feedback_log = os.getenv("AEGIS_WEB_FEEDBACK_LOG", f"{config_dir}/feedback.log")


class Feedback(BaseModel):
    """
    Data structure for feedback.
    """

    feature: str = Field(..., max_length=100)

    @field_validator("feature")
    @classmethod
    def sanitize_feature(cls, feature: str) -> str:
        return sanitize_input(feature)

    cve_id: Optional[CVEID] = Field("", max_length=50)

    email: Optional[str] = Field("", max_length=100)

    @field_validator("email")
    @classmethod
    def sanitize_email(cls, email: str) -> str:
        return sanitize_input(email)

    request_time: Optional[str] = Field("", max_length=50)

    @field_validator("request_time")
    @classmethod
    def sanitize_request_time(cls, request_time: str) -> str:
        return sanitize_input(request_time)

    actual: Optional[str] = Field("", max_length=50)

    @field_validator("actual")
    @classmethod
    def sanitize_actual(cls, actual: str) -> str:
        return sanitize_input(actual)

    expected: Optional[str] = Field("", max_length=50)

    @field_validator("expected")
    @classmethod
    def sanitize_expected(cls, expected: str) -> str:
        return sanitize_input(expected)

    accept: bool = Field(False)


def sanitize_input(text) -> str:
    """
    basic content sanitize.
    """

    if text:
        # The regex "[^a-zA-Z0-9, -,^\x20-\x7E]" does:
        #    a-zA-Z0-9: allow all uppercase letters, lowercase letters, and digits.
        #    -: allow hyphen
        #    @: allow apersand
        #    -: allow standard hypen
        return re.sub(r"[^a-zA-Z0-9 .,_–,@-]", "", text)
    return ""


def setup_feedback_logger(level=logging.INFO):
    """Setup feedback logger."""

    handler = RotatingFileHandler(
        feedback_log,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    formatter = logging.Formatter("%(asctime)s - %(message)s")

    handler.setFormatter(formatter)
    logger = logging.getLogger("feedback_logger")
    logger.setLevel(level)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger
