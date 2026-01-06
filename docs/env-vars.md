# ENVIRONMENT VARIABLES

# General settings
| Environment Variable           | Description                                     | Default Value          |
|--------------------------------|-------------------------------------------------|------------------------|
| `AEGIS_CLI_FEATURE_AGENT`      | Set to `redhat` to use rh profile               | `public`               |
| `AEGIS_LLM_HOST`               | Aegis LLM host                                  | `localhost:11434`      |
| `AEGIS_LLM_MODEL`              | Aegis LLM model                                 | `llama3.2:latest`      |
| `AEGIS_LLM_TEMPERATURE`        | Aegis LLM default temperature                   | 0.055                  |
| `AEGIS_LLM_TOP_P`              | Aegis LLM default top_p                         | .8                     |
| `AEGIS_LLM_MAX_TOKENS`         | Aegis LLM max tokens (0 means model default)    | 0                      |
| `AEGIS_LLM_INPUT_TOKENS_WARN_THR` | Threshold for LLM input tokens to log a warning | 65536               |
| `AEGIS_LLM_MAX_JOBS`           | Number of LLM prompts running concurrently      | 4                      |
| `AEGIS_LLM_TIMEOUT_SECS`       | Timeout in seconds for a single LLM prompt      | 300                    |
| `AEGIS_LOG_FILE`               | Optional log file (logs always go to stderr)    |                        |
| `AEGIS_SAFETY_ENABLED`         | Enable separate model to check model safety     | `false`                |
| `AEGIS_SAFETY_LLM_HOST`        | Safety LLM host                                 | `localhost:11434`      |
| `AEGIS_SAFETY_LLM_MODEL`       | Safety LLM model                                | `granite3-guardian-2b` |
| `AEGIS_SAFETY_OPENAPI_KEY`     | Safety openai key                               |                        |
| `AEGIS_ML_CVE_DATA_DIR`        | Directory containing CVE training data          |                        |
| `AEGIS_AGENT_MAX_RETRIES`      | Agent max retries                               | 5                      |


# REST API settings
| Environment Variable       | Description                               | Default Value                     |
|----------------------------|-------------------------------------------|-----------------------------------|
| `AEGIS_WEB_FEATURE_AGENT`  | Set to `redhat` to use rh profile         | `public`                          |
| `AEGIS_WEB_SPN`            | Service Principal Name for Kerberos auth  |                                   |
| `KRB5_KTNAME`              | Path to the keytab file for Kerberos auth | `/etc/krb5.keytab`                |
| `AEGIS_CORS_TARGET_REGEX`  | CORS origin URLs specified by a regex     | `http(s)?://localhost(:5173)?`    |
| `AEGIS_WEB_FEEDBACK_LOG`   | Feedback log file (CSV format)            | `~/.config/aegis_ai/feedback.csv` |
| `AEGIS_WEB_ENABLE_CONSOLE` | Enable web console                        | `false`                           |


# Tool settings
| Environment Variable                   | Description                           | Default Value            |
|----------------------------------------|---------------------------------------|--------------------------|
| `AEGIS_OSIDB_SERVER_URL`               | OSIDB REST API host                   | `https://localhost:8000` |
| `AEGIS_OSIDB_RETRIEVE_EMBARGOED`       | Enable retrieving embargoed CVEs      | `false`                  |
| `AEGIS_USE_CWE_TOOL_CONTEXT`           | Enable MITRE CWE tool                 | `true`                   |
| `AEGIS_CWE_TOOL_ALLOWED_CWE_IDS`       | Allowed CWE IDs for MITRE CWE tool    |                          |
| `AEGIS_USE_CISA_KEV_TOOL_CONTEXT`      | Enable CISA KEV tool                  | `false`                  |
| `AEGIS_USE_LINUX_CVE_TOOL_CONTEXT`     | Enable Linux kernel CVE tool          | `false`                  |
| `AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT`    | Enable GitHub MCP tool                | `false`                  |
| `GITHUB_PERSONAL_ACCESS_TOKEN`         | GitHub personal access token          |                          |
| `AEGIS_USE_WIKIPEDIA_TOOL_CONTEXT`     | Enable Wikipedia search tool          | `false`                  |
| `AEGIS_USE_WIKIPEDIA_MCP_CONTEXT`      | Enable Wikipedia MCP tool             | `false`                  |
| `AEGIS_USE_PYPI_MCP_CONTEXT`           | Enable PyPI MCP tool                  | `false`                  |
| `AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT` | Enable NVD MCP tool                   | `false`                  |
| `NVD_API_KEY`                          | NVD API key (for NVD MCP tool)        |                          |
| `AEGIS_USE_TAVILY_TOOL_CONTEXT`        | Enable Tavily web search tool         | `false`                  |
| `TAVILY_API_KEY`                       | Tavily API key                        |                          |


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
