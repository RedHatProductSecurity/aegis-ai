# Unit Test suite for Aegis features

This test suite is designed to run unit tests with mocked llm and tooling.

## Running the test suite

To run the entire test suite, run the following command in the top-level directory of this repository:
```commandline
make test
```

To run a specific test:
```commandline
uv run pytest -k "test_suggest_impact_with_test_model"
```

To run a specific test with live llm/tooling:
```commandline
TEST_ALLOW_CAPTURE="true" uv run pytest -k "test_suggest_impact_with_test_model"
```

## Developing new tests

When developing new tests or working on old tests one may have to recapture test data. 

To recapture set env var:

```commandline
export TEST_ALLOW_CAPTURE="true" 
```
