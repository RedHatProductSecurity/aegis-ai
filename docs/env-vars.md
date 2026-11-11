# ENVIRONMENT VARIABLES

# General settings
| Environment Variable           | Description                                     | Default Value          |
|--------------------------------|-------------------------------------------------|------------------------|
| `AEGIS_CLI_FEATURE_AGENT`      | Set to `redhat` to use rh profile               | `public`               |
| `AEGIS_LLM_HOST`               | Aegis LLM host                                  | `localhost:11434`      |
| `AEGIS_LLM_MODEL`              | Aegis LLM model                                 | `llama3.2:latest`      |
| `AEGIS_LLM_PROVIDER`           | Force the API to speak: `openai`, `anthropic` or `google`. Unset means infer it from `AEGIS_LLM_HOST`. Needed for gateways (EnMaaS, LiteLLM, ...) serving a non-OpenAI API | |
| `AEGIS_LLM_API_KEY`            | Provider-neutral API key. Unset means use the vendor variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) | |
| `AEGIS_LLM_MAX_TOKENS`         | Aegis LLM max tokens (0 means model default)    | 0                      |
| `AEGIS_LLM_INPUT_TOKENS_WARN_THR` | Threshold for LLM input tokens to log a warning | 131072              |
| `AEGIS_LLM_MAX_JOBS`           | Number of LLM prompts running concurrently      | 4                      |
| `AEGIS_LLM_TIMEOUT_SECS`       | Timeout in seconds for a single LLM prompt      | 200                    |
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
| `AEGIS_WEB_PROGRAMMATIC_FEEDBACK_LOG` | Programmatic feedback log file (CSV format) | `~/.config/aegis_ai/programmatic_feedback.csv` |
| `AEGIS_BOT_KPI_CACHE_DIR`  | Directory for KPI caches and delivery run files. Multiple replicas require shared storage with working cross-host `flock` semantics for replay and continuation; deployment storage/configuration must be verified separately | `~/.config/aegis_ai/osidb_bot_kpi` |
| `AEGIS_BOT_KPI_MAX_REFRESH_SECS` | Shared scheduling budget for OSIDB index/detail calls and transient retry delays; range 1-600, overridden by `max_refresh_secs`. Spent budgets return 200 deferrals. Not a hard end-to-end deadline: eager bindings Kerberos authentication, requests connection/read inactivity timeouts, and file lock waits do not impose a total elapsed-time bound | `20` |
| `AEGIS_BOT_KPI_INDEX_TTL_SECS` | Lifetime of the authorization/filter-scoped selection index reused when creating delivery runs; range 1-3600. Detected selection/detail inconsistency invalidates it immediately | `300` |
| `AEGIS_BOT_KPI_RUN_TTL_SECS` | Delivery run validity, measured from creation, range 60-86400. Expired continuations return 410 rather than mixing populations | `1800` |
| `AEGIS_WEB_ENABLE_CONSOLE` | Enable web console                        | `false`                           |

## osidb-bot KPI delivery protocol

All responses are served through stable delivery runs. The first response
establishes an opaque `delivery.run_id`, reports `received_flaws: 0`, and
returns `delivery.continue_token` if the selection is nonempty. Continue with
the same filters, detail/limit settings, authorization, `run_id`, and opaque
`cursor`. Each response carries:

- `delivery: {run_id, page_id, continue_token, received_flaws, selected_flaws, complete, selection_complete, deferred}`.
  Received counts selected flaws delivered, including flaws emitting no records;
  it is independent of global cache freshness and contributing flaw counts.
- Authoritative cumulative `features`, `total_flaws_processed`, and (with detail)
  `available_components`. Replace prior aggregates with these values.
- `entries` for only the current page. Accumulate unique `(run_id, page_id)` pages.
  Replaying an accepted run/cursor returns the same page and cumulative snapshot.

When the remaining budget cannot support a useful HTTP attempt, the endpoint
returns **200**, never an outage solely because its budget was spent. A zero-work
delivery response has `deferred: true`, empty entries, unchanged received counts,
and the **same** continue_token. A continuation deferral's page_id has a `:deferred` suffix and is distinct
from the eventual accepted page. Continue that cursor with a fresh request budget;
do not freeze it as an accepted-page replay. Partial accepted prefixes still use
normal advancing cursors. While index discovery is pending,
`selection_complete: false`, `selected_flaws: 0` (unknown), and `complete: false`.
Each successful index HTTP page is persisted with its offset, so the next request
resumes discovery instead of starting the index over.

Membership is frozen once index discovery completes, or comes from a scoped
selection index up to the index TTL old; values are observed when fetched. This is not an atomic OSIDB
historical snapshot. Accepted observations are copied into the run and never
replaced by another request's cache updates. Missing flaws or changed watermarks
detected during fetching invalidate the run and selection index.

HTTP 503 and genuine requests connection/read-timeout failures receive at most
three retries after the initial attempt,
with bounded exponential delays and remaining-budget timeouts on iterator calls.
Other HTTP errors, certificate/authentication errors, and filesystem errors are
not retried by Aegis. An attempt and delay must fit the remaining request budget;
the minimum attempt allowance is one second or one quarter of a shorter original
budget. Actual outbound timeouts are recomputed before initial calls and retries,
without a one-second timeout floor. Attempt counts persist across delivery/index
budget deferrals, preventing a fresh budget from resetting upstream retries.
Concurrent requests sharing a selection merge their failure counts into one
shared allowance; calls already in flight when the allowance is spent may still
complete, so the total can exceed the cap by at most the number of concurrent
requests.
Only actual upstream retry exhaustion returns top-level `retry_exhausted: true` with `detail` (and
`run_id` when available); the failed continuation remembers exhaustion, so replay
does not launch another set of upstream retries. Pre-run selection failures have
a 30-second scoped exhaustion cooldown. Clients may retry unmarked 503 responses,
but must stop on the exhaustion marker. Successful batches are persisted before
fetching another batch and can be reused on a subsequent explicit refresh.

On 409 `code: kpi_run_invalidated` or 410 `code: kpi_run_expired`, retain the last
valid partial response and ask the user to refresh. A manual refresh omits run_id
and cursor, creating a new run. Verified middleware principals scope the shared
flaw cache independently of filters, scoring options, and page size. Selection
caches add only flaw-selection filters; runs additionally bind scoring/detail/
limit options. Token rotation preserves a run when that verified principal is
available. If no verified principal is available, a token digest is used instead
and rotation then changes scope; JWT claims are never trusted without validation.
Service-credential requests use the resolved Kerberos principal. The prior
unscoped cache is not migrated into the principal-scoped delivery cache.

On KPI traffic, maintenance checks at most once per minute and removes expired
run and old selection files across scoped directories after the run TTL. A
directory guard and nonblocking file locks prevent deleting active/open state;
active expired files are retried on a later sweep. Shared compact flaw caches and
small directory guard files are retained for reuse. Cleanup is traffic-driven,
not a background scheduler, and requires the same cross-host locking semantics.
Selection hit/miss, index/detail timing, cache hit/miss counts, page replay, and
invalidation events are logged.


# Tool settings
| Environment Variable                   | Description                           | Default Value            |
|----------------------------------------|---------------------------------------|--------------------------|
| `AEGIS_BOMQ_URL`                       | bomq REST API host                    | `https://localhost:8080` |
| `AEGIS_BOMQ_COMMUNITY_URL`             | Community bomq REST API. Empty skips that catalog. | `https://localhost:8081` |
| `AEGIS_ANITYA_URL`                     | release-monitoring.org API            | `https://release-monitoring.org` |
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
| `AEGIS_USE_EXT_REFS_TOOL_CONTEXT`      | Enable external references tool (fetches content from CVE reference URLs on an allowlist of trusted domains) | `false` |
| `AEGIS_USE_BUILD_SYSTEM_TOOL_CONTEXT`  | Enable build system tool (Brew/bomq binary RPM lookup for `SuggestAffectedPackages`) | `false` |
| `AEGIS_USE_OSV_DEV_TOOL_CONTEXT`         | Enable OSV.dev tools (`osv_dev_cve_tool` and `osv_dev_ghsa_tool`) | `true` |
| `AEGIS_USE_OSIDB_COMPONENT_TOOL_CONTEXT` | Enable OSIDB component tools (`component_count_tool` and `component_flaw_tool`) | `false` |
| `AEGIS_USE_TAVILY_TOOL_CONTEXT`        | Enable Tavily web search tool         | `false`                  |
| `TAVILY_API_KEY`                       | Tavily API key                        |                          |


# Kernel classifier settings
| Environment Variable             | Description                                                          | Default Value                |
|----------------------------------|----------------------------------------------------------------------|------------------------------|
| `AEGIS_KERNEL_CLASSIFIER_DIR`    | Path to the classifier directory containing `models/` and `cve_feature_extraction.py` | co-located `aegis_ai_ml` source tree |
| `AEGIS_USE_KERNEL_CLASSIFIER`    | Enable kernel-specific CVE impact classifier                         | `false`                      |
| `AEGIS_DISABLE_HTML_FEATURES`   | Set to `true` to disable HTML feature supplement during training (ablation testing) | `false` (enabled)            |


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
| `AEGIS_EVALS_MIN_PASSED`    | How many evals need to succeed to exit successfully | |
| `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE` | suggest-affected-components eval: randomly sample N CVEs (reduces API usage) | (all qualifying) |
| `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE_SEED` | suggest-affected-components eval: random seed for sampling (reproducible runs) | 42 |
| `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS` | suggest-affected-components eval: comma-separated CVE IDs to restrict cases to | (all qualifying in cache) |
| `AEGIS_LOGGING_EVALS_VERBOSE` | Show tool-call logs during evals (normally suppressed) | `false` |
| `OSIDB_CACHE_DIR`           | Eval osidb cache directory | `evals/osidb_cache` |
