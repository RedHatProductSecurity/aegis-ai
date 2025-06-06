# test_agent.py
import os
import pytest

from dotenv import load_dotenv

from deepeval import evaluate
from deepeval.metrics import (
    FaithfulnessMetric,
)
from deepeval.test_case import LLMTestCase
from deepeval.dataset import EvaluationDataset

load_dotenv()

print(f"API Key loaded: {os.getenv('OPENAI_API_KEY') is not None}")

# Define a dataset for evaluation
# In a real scenario, this would come from a CSV, JSON, or a database.
# For simplicity, we define it programmatically.
dataset = EvaluationDataset()

# Test Case 1: Simple weather query
dataset.add_test_case(
    LLMTestCase(
        input="Add two plus two",
        actual_output="Placeholder - will be overwritten in dynamic test",
        expected_output="2 + 2 = 4",
        retrieval_context=[],
    )
)


@pytest.mark.skip(reason="This feature is not yet implemented")
@pytest.mark.parametrize("test_case", dataset)
def test_agent_response(agent, test_case: LLMTestCase):
    test_case.actual_output = agent.run_sync(test_case.input).output
    faithfulness_metric = FaithfulnessMetric(threshold=0.7)  # Expect 70% faithfulness
    evaluate(
        test_cases=[test_case],  # evaluate expects a list
        metrics=[
            faithfulness_metric,
        ],
    )
