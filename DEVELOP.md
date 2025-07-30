# Aegis Development Guide

This document outlines the core principles, architecture, and development practices for the Aegis project.

[Review adrs](docs/adrs)
-----

## Architecture

Aegis uses Large Language Models (LLMs) to perform advanced security analysis and operations. Its architecture is built on four key principles:

  * **Pydantic Data Models**: We enforce data integrity by using Pydantic models to define the expected structure for both LLM inputs and outputs. This provides type safety, validation, and reduces prompt engineering complexity.

  * **Autonomous Agents**: Aegis Agents, built with `pydantic-ai`, orchestrate all interactions with the LLM. They autonomously decide when and how to use available tools, making them adaptable for diverse tasks.

  * **RAG for In-Context Data**: We use Retrieval Augmented Generation (RAG) to provide private, up-to-date information to the LLM. By integrating with systems like OSIDB and a `pgvector` knowledge base, we ensure our agents have the specific context needed for accurate, relevant responses.

  * **Extensible Features**: Features are self-contained capabilities that an agent can use. They bundle a specific prompt, an output model, and any necessary logic, allowing for modular and scalable development.

-----

## Adding a New Feature

Follow these steps to create and integrate a new feature:

1.  **Define the Goal & Prompt**: Clearly define what the feature should accomplish and write a precise prompt to instruct the LLM. Test the prompt iteratively.
2.  **Define the Output Model**: Create a Pydantic `BaseModel` that defines the structure of the data you expect back from the LLM.
3.  **Implement the Feature**: Add a new module under the `src/aegis/features/` directory that combines the prompt and the Pydantic output model.
4.  **Provide Context (If Needed)**: If the feature requires external data, either integrate a new tool or add relevant documents to the RAG knowledge base.
5.  **Write Tests & Expose**: Add unit tests for the feature. Expose the new capability through the project's CLI and/or REST API.

-----

## Getting Started

Aegis development is managed with **`uv`**, a fast Python package installer and resolver.

#### \#\#\# Setup

1.  **Install `uv`**:

    ```bash
    pip install uv
    ```

2.  **Sync Dependencies**: Install all project dependencies, including development tools. `uv` will create and manage a virtual environment automatically in `.venv`.

    ```bash
    uv sync --all-extras
    ```

#### \#\#\# Running Aegis

  * **Run a Script**:
    ```bash
    uv run python scripts/<script_name>.py
    ```
  * **Start the REST API**:
    ```bash
    uv run uvicorn src.aegis_ai_web.src.main:app --port 9000
    ```
  * **Launch the CLI**:
    ```bash
    uv run aegis --help
    ```

#### \#\#\# Managing Dependencies

  * **Add a New Dependency**:
    ```bash
    uv add numpy
    ```
  * **Add a Development-Only Dependency**:
    ```bash
    uv add --dev mypy
    ```

-----

## Code Quality

We enforce code quality using **`ruff`** for linting and formatting. These checks are run automatically in CI.

  * **Check for Linting Errors**:
    ```bash
    uvx ruff check .
    ```
  * **Apply Formatting**:
    ```bash
    uvx ruff format .
    ```

-----

## Configuration

Configure Aegis via environment variables, typically loaded from a `.env` file in the project root. For LLM authentication, set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` as environment variables.

**Example `.env` file:**

```ini
# AEGIS CLI default agent
AEGIS_CLI_FEATURE_AGENT="redhat"

# LLM Connection Details
AEGIS_LLM_HOST="https://generativelanguage.googleapis.com"
AEGIS_LLM_MODEL="gemini-2.5-pro"
GEMINI_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Enable OTEL
AEGIS_OTEL_ENABLED="true"
OTEL_EXPORTER_OTLP_ENDPOINT='http://localhost:4318'

# Recapture LLM results to cache in tests
TEST_ALLOW_CAPTURE="true"

# Tooling API Keys and URLs
NVD_API_KEY="XXXXXXXXXXXXXXXXXXXXXXX"
TAVILY_API_KEY="tvly-dev-XXXXXX"

# OSIDB bindings conn details
AEGIS_OSIDB_SERVER_URL="https://osidb-stage.example.com"
AEGIS_OSIDB_RETRIEVE_EMBARGOED=false

# Required for environments with custom SSL certificates
REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"


```

-----

## Testing

Our test suite uses **`pytest`** and `pytest-asyncio`.

  * **Run All Tests**:
    ```bash
    make test
    ```
  * **Run a Specific Test by Name**:
    ```bash
    uv run pytest -k "test_suggest_impact_with_bad_cve"
    ```

-----

## Registering MCP

Add MCP servers to aegis_ai.toolsets

-----

## Publishing & Releasing

#### Build and Publish to PyPI

1.  **Build the Distribution**:
    ```bash
    make build-dist
    ```
2.  **Publish to PyPI**: Set your credentials and run the publish command.
    ```bash
    export TWINE_USERNAME=__token__
    export TWINE_PASSWORD=pypi-your-long-api-token-string-here

    make publish-dist
    ```

####  Making a Release

Aegis uses semantic versioning.

1.  **Create a Release Branch**: Create a new branch for the release (e.g., `release-prep/v1.1.2`).
2.  **Update Version**: Increment the version number in `pyproject.toml`.
3.  **Update Changelog**: Add the release notes to `docs/CHANGELOG.md`.
4.  **Sync Lockfile**: Update `uv.lock` by running `make` or `uv lock`.
5.  **Submit PR**: Create a pull request, get it reviewed, and merge it into the main branch.
6.  **Tag and Release**: Create a new tag and release on GitHub from the main branch. The tag (e.g., `v1.1.2`) will trigger the CI pipeline to build and publish the package to PyPI.