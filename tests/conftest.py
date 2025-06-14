import pytest

from pydantic_ai import models
from pydantic_ai.models.test import TestModel

from aegis.agents import rh_feature_agent


@pytest.fixture(scope="session", autouse=True)
def disable_model_requests():
    # prevent any real LLM API calls during tests
    models.ALLOW_MODEL_REQUESTS = False


@pytest.fixture(scope="session", autouse=True)
def override_rh_feature_agent():
    m = TestModel()
    m.call_tools = ""
    with rh_feature_agent.override(model=m):
        yield
