# Web API Test Cache

This directory contains cached API responses from end-to-end tests that make LLM calls.

## Purpose

Caching API responses allows tests to run quickly without incurring LLM API costs on every test run.

## Usage

### Running Tests with Cache (Default)

By default, tests will use cached responses:

```bash
make test-web
# or
uv run pytest src/aegis_ai_web/tests
```

### Recapturing Cache (Making Fresh LLM Calls)

To make fresh LLM calls and update the cache, delete the cache file:

```bash
rm src/aegis_ai_web/tests/api_cache/test_submit_feedback_after_suggest_impact_analysis.json
uv run pytest src/aegis_ai_web/tests/test_feedback.py::test_submit_feedback_after_suggest_impact_analysis
```

## Cache Files

Each test function that uses the cache will have its own JSON file named after the test function.

Example:
- `test_submit_feedback_after_suggest_impact_analysis.json` - Cached response for the suggest-impact → feedback E2E test

## Version Control

Cache files should be committed to version control so that CI/CD and other developers can run tests without LLM costs.

