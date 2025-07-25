import os

import pytest
from pydantic_ai import models

from aegis_ai import config_logging

test_allow_recapture: bool = os.getenv("TEST_ALLOW_CAPTURE", "false").lower() in (
    "true",
    "1",
    "t",
    "y",
    "yes",
)


@pytest.fixture(scope="session", autouse=True)
def setup_logging_for_session():
    config_logging(level="INFO")


@pytest.fixture(scope="session", autouse=True)
def disable_model_requests():
    # Set to True to enable capturing of llm calls to cache.
    if test_allow_recapture:
        models.ALLOW_MODEL_REQUESTS = True
    else:
        models.ALLOW_MODEL_REQUESTS = False
