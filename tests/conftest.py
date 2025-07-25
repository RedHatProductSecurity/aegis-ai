import os

import pytest
from pydantic_ai import models
from pydantic_ai.models.test import TestModel


from aegis import config_logging
from aegis.agents import rh_feature_agent

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
        m = TestModel()
        # m.call_tools = ""
        with rh_feature_agent.override(model=m):
            yield
