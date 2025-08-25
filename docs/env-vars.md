# ENVIRONMENT VARIABLES

# General settings
| Environment Variable           | Description                                 | Default Value |
|--------------------------------|---------------------------------------------|---------------|
| `AEGIS_CLI_FEATURE_AGENT`      | Set to `redhat` to use rh profile           | `public`      |
| `AEGIS_WEB_FEATURE_AGENT`      | Set to `redhat` to use rh profile           | `public`      |
| `AEGIS_LLM_HOST`               | Aegis LLM host                              |               |
| `AEGIS_LLM_MODEL`              | Aegis LLM model                             |               |
| `AEGIS_SAFETY_ENABLED`         | Enable separate model to check model safety | `false`       |
| `AEGIS_SAFETY_LLM_HOST`        | Safety LLM host                             | `false`       |
| `AEGIS_SAFETY_LLM_MODEL`       | Safety LLM model                            | `false`       |
| `AEGIS_SAFETY_OPENAPI_KEY`     | Safety openai key                           | `false`       |
| `AEGIS_ML_CVE_DATA_DIR`        | Directory containing CVE training data      |               |


# Tool settings
| Environment Variable               | Description                                  | Default Value |
|------------------------------------|----------------------------------------------|---------------|
| `AEGIS_OSIDB_SERVER_URL`           | OSIDB REST API host                          |               |
| `AEGIS_OSIDB_RETRIEVE_EMBARGOED`   | Enable retrieving embargoed                  | `false`       |
| `AEGIS_USE_TAVILY_TOOL_CONTEXT`    | Use Tavily search api tool                   | `false`       |
| `TAVILY_API_KEY`                   | Use Tavily search api tool                   |               |
| `NVD_API_KEY`                      | Use NVD tool (for public)                    |               |
| `AEGIS_USE_CWE_TOOL_CONTEXT`       | Use mitre CWE tool                           | `false`       |
| `AEGIS_USE_LINUX_CVE_TOOL_CONTEXT` | Use linux kernel tool                        | `false`       |


# Instrumenting/logging settings
| Environment Variable               | Description                                  | Default Value |
|------------------------------------|----------------------------------------------|---------------|
| `AEGIS_OTEL_ENABLED`               | Enable OTEL log events                       | `false`       |
| `OTEL_EXPORTER_OTLP_ENDPOINT`      | Export OTEL                                  |               |


# Test settings
| Environment Variable               | Description                | Default Value |
|------------------------------------|----------------------------|---------------|
| `TEST_ALLOW_CAPTURE`               | Enable llm cache recapture | `false`       |
| `TEST_LLM_CACHE_DIR`               | Test LLM cache dir         |               |


# Eval settings
| Environment Variable        | Description                | Default Value |
|-----------------------------|----------------------------|--------------|
| `AEGIS_EVALS_LLM_HOST`      | Eval LLM host              |              |
| `AEGIS_EVALS_LLM_MODEL`     | Eval LLM model             |              |
| `AEGIS_EVALS_LLM_API_KEY`   | Eval LLM openapi key       |              |
| `AEGIS_EVALS_MIN_PASSED`    | Minimum eval to pass       |              |
| `OSIDB_CACHE_DIR`           | Eval osidb cache directory | data         |