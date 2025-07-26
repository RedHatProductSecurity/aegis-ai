# Aegis Development Guide

This document outlines the core architectural principles and development practices for the Aegis project.

## Architecture Highlights

Aegis leverages the power of Large Language Models (LLMs) to enhance security operations, built upon these key principles:

* **Pydantic Data Models:** We use Pydantic to define the **expected structure of LLM outputs**. This significantly reduces prompt engineering complexity, ensuring our agents receive reliable, structured data.
* **`pydantic-ai` Agents:** Our custom `pydantic-ai` Agents orchestrate all interactions with the LLM. They autonomously decide when and how to utilize available tools, making them adaptable for diverse conversational and analytical tasks.
* **Custom RAG Integrations:** We provide **private, in-context data** to the LLMs through integrations with systems like OSIDB and RHTPAv2. This Retrieval Augmented Generation (RAG) ensures LLMs have the specific, up-to-date information needed for accurate responses.
* **Extensible Features:** Features serve as the primary mechanism for extending Aegis's capabilities, allowing for modular and scalable development.

Pydantic ai provides safety and guardrails via pydantic data models for input and defining `output-format` for all output from llm.

---

## Adding a new feature

The rough steps to creating a new feature:

1) develop a prompt (test prompt with developer console)
2) identify if any new context is needed (might need a need tool integration or upload of facts/content into pgvector)
3) add under appropriate features/ ensuring to define both prompt and pydantic data model
4) write test, expose example usage in cli and rest server

## Getting Started

Aegis development is powered by **`uv`**, the Python package installer and executor.

Install uv for your user (eg. no need to create project venv as uv will do all that)

```commandline
pip install uv
```

### Running Aegis

You can execute any application script with `uv run`:

```commandline
uv run python scripts/<script-name>
```

To start the Aegis REST API service:

```commandline
uv run uvicorn src.aegis_restapi.main:app --port 9000
```

To launch the Aegis Command-Line Interface (CLI):
```commandline
uv run aegis
```

### Setup RAG knowledgebase
To run a local postgres with pgvector - which is used for additional RAG context.
```commandline
cd etc/deploy && podman-compose up --build
```

### Managing Dependencies
`uv` simplifies dependency management:

* **Synchronize All Dependencies:** Install all project dependencies, including development extras:
    ```commandline
    uv sync --all-extras --dev
    ```
* **Add a New Dependency:**
    ```commandline
    uv add numpy
    ```
* **Add a Development-Only Dependency:**
    ```commandline
    uv add --dev mypy
    ```

---


## Code Quality
We enforce code quality using **`ruff`** for linting and formatting.

### Linting & Formatting Checks
To check for linting errors:

```commandline
uvx ruff check
```

To verify code formatting:

```commandline
uvx ruff format --check
```

### Automatic Formatting

If `ruff format --check` reports issues, you can automatically fix them:

```commandline
uvx ruff format
```

---

## Configuration
Aegis is configured via environment variables, typically loaded from a `.env` file in your project root.

Here's an example `.env` configuration:

```ini
# llm connection details
AEGIS_LLM_HOST="https://api.anthropic.com"
AEGIS_LLM_MODEL="anthropic:claude-sonnet-4-latest"

# RAG connection details and controls embedding of RAG knowledge and RAG query embedding
PG_CONNECTION_STRING="postgresql://youruser:yourpassword@localhost:5432/aegis""
AEGIS_RAG_SIMILARITY_SCORE_GT=.7
AEGIS_RAG_EMBEDDING_DIMENSION=768
AEGIS_RAG_EMBEDDING_MODEL_NAME="sentence-transformers/all-mpnet-base-v2"

# tooling
TAVILY_API_KEY="tvly-dev-XXXXXX"
AEGIS_OSIDB_SERVER_URL="https://localhost:8000"
AEGIS_OSIDB_RETRIEVE_EMBARGOED='false'

# For SSL/TLS certificate bundles, if your environment requires it:
REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
```

**Note:** For external llm models -need to set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` env vars.

---

## Testing
We use **`pytest`** for our test suite, with `pytest-asyncio` for asynchronous tests.

To run all tests:

```commandline
make test
```

Run a specific test:
```commandline
uv run pytest -k "test_suggest_impact_with_bad_cve_test_model"
```


## Build and Publish to pypi

```commandline
make build-dist
```

and to push to pypi:

```commandline
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-your-long-api-token-string-here

make publish-dist
```

## Make a Release

Aegis uses semantic versioning for all releases.

1. Create new branch (ex. v1.1.2) which is not a release branch!
  * update `aegis_ai/__init__.py#version` 
  * update `docs/CHANGELOG.md` 
  * update `pyproject.toml` version
  * update `uv.lock` by running `make`
2. Raise prep PR, review and merge 
3. Create new github release with new tag ( ex. 1.1.2 ) based on previously created branch
   * new tag triggers CI for pushing to prod
   * publishing to pypi 
