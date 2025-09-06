# ENVIRONMENT VARIABLES

# General settings
| Environment Variable           | Description                                 | Default Value |
|--------------------------------|---------------------------------------------|---------------|
| `AEGIS_CLI_FEATURE_AGENT`      | Set to `redhat` to use rh profile           | `public`      |
| `AEGIS_WEB_FEATURE_AGENT`      | Set to `redhat` to use rh profile           | `public`      |
| `AEGIS_LLM_HOST`               | Aegis LLM host                              | `localhost:11434` |
| `AEGIS_LLM_MODEL`              | Aegis LLM model                             | `llama3.2:latest` |
| `AEGIS_SAFETY_ENABLED`         | Enable separate model to check model safety | `false`       |
| `AEGIS_SAFETY_LLM_HOST`        | Safety LLM host                             | `localhost:11434` |
| `AEGIS_SAFETY_LLM_MODEL`       | Safety LLM model                            | `granite3-guardian-2b`|
| `AEGIS_SAFETY_OPENAPI_KEY`     | Safety openai key                           |               |
| `AEGIS_ML_CVE_DATA_DIR`        | Directory containing CVE training data      |               |


# Tool settings
| Environment Variable                    | Description                 | Default Value            |
|-----------------------------------------|-----------------------------|--------------------------|
| `AEGIS_OSIDB_SERVER_URL`                | OSIDB REST API host         | `https://localhost:8000` |
| `AEGIS_OSIDB_RETRIEVE_EMBARGOED`        | Enable retrieving embargoed | `false`                  |
| `AEGIS_USE_TAVILY_TOOL_CONTEXT`         | Use Tavily search api tool  | `false`                  |
| `TAVILY_API_KEY`                        | Use Tavily search api tool  |                          |
| `NVD_API_KEY`                           | Use NVD tool (for public)   |                          |
| `AEGIS_USE_CWE_TOOL_CONTEXT`            | Use mitre CWE tool          | `true`                   |
| `AEGIS_USE_LINUX_CVE_TOOL_CONTEXT`      | Use linux kernel tool       | `false`                  |
| `AEGIS_USE_GITHUB_MCP_CONTEXT`          | Use github mcp tool         | `true`                   |
| `GITHUB_PERSONAL_ACCESS_TOKEN`          | Use linux kernel tool       |                          |
| `AEGIS_USE_WIKIPEDIA_MCP_CONTEXT`       | Use wikipedia mcp tool      | `false`                  |
| `AEGIS_USE_PYPI_MCP_CONTEXT`            | Use pypi mcp tool           | `false`                  |
| `AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT`  | Use nvd mitre tool          | `false`                  |


# Instrumenting/logging settings
| Environment Variable               | Description                                  | Default Value |
|------------------------------------|----------------------------------------------|---------------|
| `AEGIS_OTEL_ENABLED`               | Enable OTEL log events                       | `false`       |
| `OTEL_EXPORTER_OTLP_ENDPOINT`      | Export OTEL                                  |               |


# Test settings
| Environment Variable               | Description                | Default Value |
|------------------------------------|----------------------------|---------------|
| `TEST_ALLOW_CAPTURE`               | Enable llm cache recapture | `false`       |
| `TEST_LLM_CACHE_DIR`               | Test LLM cache dir         | `tests/llm_cache` |


# Eval settings
| Environment Variable        | Description                | Default Value |
|-----------------------------|----------------------------|---------------|
| `AEGIS_EVALS_LLM_HOST`      | Eval LLM host              |               |
| `AEGIS_EVALS_LLM_MODEL`     | Eval LLM model             |               |
| `AEGIS_EVALS_LLM_API_KEY`   | Eval LLM openapi key       |               |
| `AEGIS_EVALS_MIN_PASSED`    | Minimum eval to pass       |               |
| `OSIDB_CACHE_DIR`           | Eval osidb cache directory | `evals/osidb_cache` |
