import pytest

from aegis.agents import feature_agent


@pytest.fixture(scope="module")
def agent():
    return feature_agent
