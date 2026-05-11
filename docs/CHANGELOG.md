# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-05-11

### Changed
- `suggest-impact` now incorporates kernel patch context and integrates the kernel impact classifier for severity reconciliation on kernel CVEs
- the `suggest-impact` explanation is revised when the kernel classifier adjusts the score or impact

### Added
- added `--refresh-cache` flag to regenerate OSIDB cache entries in evals
- added verbose pipeline diagnostics to `suggest-impact`
- added evaluation cases and annotations based on feedback from security analysts
- documented eval framework, environment variables, and guardrail docstrings

### Fixed
- improved `suggest-affected-components` accuracy and Chromium sub-component mapping
- do not suggest sub-services as separate affected components
- addressed security scanner findings in OpenAPI and container image
- deferred safety agent import until after the enabled check


## [0.6.3] - 2026-04-27

### Changed
- improved kernel CVE classifier training pipeline with better feature extraction
- retrained kernel classifier with 83 additional IMPORTANT CVEs and expanded test set
- penalize long lists in the output of `suggest-affected-components` evals
- exclude `affects` from the input of `suggest-affected-components`

### Added
- added kernel impact classifier runtime module
- added evaluation cases and annotations based on feedback from security analysts
- CI can skip evals when the PR description contains `CI: skip-pr-evals`

### Fixed
- improved LLM prompt templates based on feedback
- do not suggest fields unrelated to a specific feature
- do not suggest `title` and `components` in `suggest-cwe`
- do not mention exploit availability in suggestions
- added a hint for CWE-617 to CWE tool
- improved error handling in `component-intelligence` API endpoint
- improved handling of OSIDB auth and lookup failures
- improved handling of validation errors in feedback API endpoints
- made certain fields required in feedback API endpoints
- avoid logging of GSSAPI tracebacks in non-debug mode


## [0.6.2] - 2026-03-23

### Added
- added a few more annotations for occasionally failing evaluation cases

### Fixed
- adjusted prompt so drafted statements do not show the impact in all caps
- improved handling of `osidb-bot` authentication failures while connecting to OSIDB


## [0.6.1] - 2026-03-18

### Changed
- `osidb-bot` does not refuse to connect to production OSIDB anymore
- `osidb-bot` now processes flaws with empty state, too

### Added
- added a few more annotations for occasionally failing evaluation cases

### Fixed
- OSIDB bot response text on failure is now truncated in `osidb-bot` log messages


## [0.6.0] - 2026-03-13

### Changed
- Aegis CLI is now much faster in case no time-consuming task is actually triggered
- evaluation suite log is now less verbose to avoid log truncation by CI providers

### Added
- introduced the `suggest-affected-components` feature in Aegis CLI and REST API, covered by evals
- added support for delegation of Kerberos credentials from REST API to AI-initiated OSIDB tool calls
- introduced the `osidb-bot` command to save suggestions directly to OSIDB without any user interaction
- added logging of e-mails that do not match the authenticated Kerberos user on the feedback endpoints
- asynchronous scoring of semantic proximity based on `LLMJudge` on the `programmatic-feedback` endpoint
- implemented LLM prompt retry on `ModelHTTPError: status_code: 500` to eliminate intermittent failures

### Fixed
- aligned `impact` with `cvss3_score` in case LLM suggested a contradicting `impact` value
- Aegis does not transitively depend on `python-diskcache-5.6.3`, which was vulnerable, any more
- the `component-intelligence` Aegis feature now works again
- improved handling of timeouts on Gemini API to make it work with lower `AEGIS_LLM_TIMEOUT_SECS`
- improved evaluation suite log to ease debugging of CI failures
- improved initialization of `LLMJudge` to support additional evaluation configurations
- adapted evaluation suite to work reliably with the latest version of Gemini API


## [0.5.3] - 2026-01-27

### Changed
- lowered verbosity of the CWE toolset, which does not need to be debugged any more

### Added
- added `/api/v1/programmatic-feedback` REST API endpoint for automatic feedback collection
- added evaluation cases based on the feedback from security analysts

### Fixed
- fixed data validation errors with `deepseek-ai/DeepSeek-R1-Distill-Qwen-32B` used as LLM
- fixed compatibility with `pydantic-ai-slim-1.46.0` when Gemini API is used as LLM
- tweaked the `suggest-statement` LLM prompt based on feedback to improve suggestions
- added handling for JSON decoding errors


## [0.5.2] - 2026-01-19

## Fixed
- an interim fix for OSIM-submitted feedback (read `cveId` if `cve_id` is not available)


## [0.5.1] - 2026-01-14

### Changed
- enabled GPU acceleration in `SecBERT` fine-tuning (bringing approx. 300x speedup)
- the `wikipedia` tool (introduced in Aegis 0.2.6) is no longer enabled by default
- dropped the constraint on the highest Python version

### Added
- introduced `HIGH_CONFIDENCE_PENALTY_DIVISOR` parameter in evals to provide more useful score
- the `SecBERT` classifier is now included in the container image for ML experiments
- added evaluation cases based on the feedback from security analysts
- updated/extended Aegis documentation and improved its structure


## [0.5.0] - 2025-12-18

### Changed
- improved `suggest-description` based on a CVE Description Gem used by security analysts at Red Hat
- the `search_cwes` tool was reimplemented using `TF-IDF` (Term Frequency-Inverse Document Frequency)
- the size of the `aegis-ai` container image was reduced from 2.89 GB to 1.14 GB

### Added
- added evaluation cases based on the feedback from security analysts
- the feedback API endpoint now supports querying for all features
- the result of the `search_cwes` tool is now logged
- a warning is now logged when a disallowed CWE is filtered out from the output of `suggest-cwe`
- long running LLM prompts are now periodically logged every 60 seconds

### Fixed
- fixed handling of the `disallowed` flag in CWE cache
- the LLM prompt is now retried on `ModelHTTPError` to recover from occasional failures of the LLM engine


## [0.4.4] - 2025-12-08

### Changed
- the feedback API endpoint now writes the data to a shared CSV file protected by a file lock
- suggested impact and CVSS score are now evaluated separately in the evaluation suite
- the evaluation suite now provides more user-friendly error messages on failure

### Added
- the feedback log now includes additional fields (rejection reason and Aegis version)
- initiation of HTTP connections is now logged (previously only their completion was logged)
- added evaluation cases based on the feedback from security analysts
- the evaluation suite now covers also the suggested CVSS vector
- added an API endpoint to query redacted data from the feedback log
- fine-grained tagging of known-to-fail cases in the evaluation suite

### Fixed
- OSIDB fields exclusion now works properly with `osidb_cache` used by the evaluation suite
- tweaked `suggest-impact` and `suggest-statement` LLM prompts to provide better suggestions


## [0.4.3] - 2025-11-25

### Changed
- bump to pydantic-evals,pydantic-ai 1.22.0
- dynamic filtering of CVE data - using data dependencies injection with `osidb_tool`
- dynamic filtering of CVE data when supplied direct with static content
- enhanced `suggest-statement` analysis feature to also suggest `mitigation`
- increased `AEGIS_LLM_INPUT_TOKENS_WARN_THR` to 65536

### Added
- added `AEGIS_LLM_TEMPERATURE`, `AEGIS_LLM_TOP_P`, and `AEGIS_LLM_MAX_TOKENS` env vars
- retry the prompt with a gradually increasing delay on an internal failure of the LLM provider
- added evaluation cases based on the feedback from security analysts
- `suggest-description` now expands all acronyms used in the description

### Fixed
- `title` and `description` are now more consistent with each other in `suggest-description`


## [0.4.2] - 2025-11-14

### Added
- extend the `suggest-cwe`, `suggest-description`, and `suggest-impact` evals based on feedback
- show expected output and the reason for assertion success/failure in the evaluation report

### Fixed
- improve quality of `suggest-description` and `suggest-impact` based on feedback


## [0.4.1] - 2025-11-11

### Changed
- bump to osidb-bindings 5.1.0
- bump to pydantic-ai 1.14.0
- decrease verbosity of `search_cwes` when not debugging

### Added
- write log messages also to a log file when the `AEGIS_LOG_FILE` environment variable is set
- log the outcome of `suggest-impact` feature

### Fixed
- make `make eval-debug` work again
- handle evaluator failures accordingly
- do not mix types in `agent_default_max_retries`
- retry prompt with high temperature when RECITATION filter triggers
- make aegis work again with `ollama`
- ensure consistency of `cvss3_{vector,score}` in `suggest-impact`


## [0.4.0] - 2025-11-04

### Changed
- web console disabled by default
- bump to pydantic-ai 1.4.0
- simplified `AegisFeatureModel` to reduce LLM overhead
- refactored agents and toolsets internals
- renamed `rewrite-{description,statement}` to `suggest-{description,statement}`, respectively
- `AEGIS_CORS_TARGET_URL` was replaced by `AEGIS_CORS_TARGET_REGEX` to support multiple CORS origins

### Added
- added `/healthz` endpoint of the web server without authentication and logging
- added `AEGIS_AGENT_MAX_RETRIES` env var defining number of times agent will retry.
- added new data_quality assessment via data critic subagent to all analysis.


## [0.3.1] - 2025-10-17

### Changed
- bump to pydantic-ai 1.1.0
- unify the logging format for tests/evals, cli and web
- trigger build of the FAISS index before starting the web service
- eliminate unneeded dependencies in the container image
- drop `Containerfile.eval` no longer maintained

### Added
- add `api/v1/feedback` REST api endpoint (and environment variable `AEGIS_WEB_FEEDBACK_LOG`)
- log start/finish of all tool calls
- extend the `suggest-cwe` evaluation suite based on the UAT feedback

### Fixed
- use stable version string in stable container images
- tweak google gemini safety settings
- set POST request timeout in `osvdev` tool


## [0.3.0] - 2025-10-10

### Added
- add `AEGIS_CWE_TOOL_ALLOWED_CWE_IDS` env var defining allowed CWE-IDs
- make the REST API support Kerberos auth (when `AEGIS_WEB_SPN` is set)
- add manpages context tool
- enable CORS on the REST API endpoint
- add `Containerfile` to build `aegis-ai` container image
- timeout (300s by default) for LLM response can be controlled by `AEGIS_LLM_TIMEOUT_SECS`
- the number of concurrently running LLM prompts (4 by default) can be controlled by `AEGIS_LLM_MAX_JOBS`
- increase coverage of `suggest-cwe` in the evaluation suite
- warning for too many LLM input tokens can be controlled by `AEGIS_LLM_INPUT_TOKENS_WARN_THR`
- add `eval-debug` target of `make`
- development snapshots of aegis now report their version based on `git describe`

### Changed
- remove dbpedia tool
- update tools User Agent (aegis - https://github.com/RedHatProductSecurity/aegis-ai)
- added some error handling for tools
- add gemini safety settings
- bump to osidb-bindings 4.16.0
- bump to pydantic-ai 1.0.14
- enhance mitre cwe tool to support similarity search (via `faiss-cpu`)
- restrict the output of `suggest-cwe` to CWEs that are included in the `CWE-699` view
- the list of CWEs returned by `suggest-cwe` is now ordered by correctness
- remove `aegis_ai_chat` example code
- the release process for aegis is now more automated

### Fixed
- the default `make` target now works on a freshly cloned git repository

## [0.2.9] - 2025-09-07

### Added
- added dbpedia tool (https://www.dbpedia.org/)
- added cisa-kev tool (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)


## [0.2.8] - 2025-09-07

### Changed
- update openapi 
- enhanced osidb tool to enumerate a given component's CVEs

## [0.2.7] - 2025-09-06

### Fixed
- fix pyproject.toml to include all assets, fixes pypi dist 


## [0.2.6] - 2025-09-06

### Added
- added cwe_tool (https://cwe.mitre.org/data/downloads.html)
- added /openapi.yml 
- added `make check-type`
- added safety agent
- added secbert classifier example to `aegis_ai_ml`
- added kernel_cve tool (https://git.kernel.org/pub/scm/linux/security/vulns.git)
- added tool env switches (AEGIS_USE_TAVILY_TOOL_CONTEXT, AEGIS_USE_CWE_TOOL_CONTEXT,AEGIS_USE_LINUX_CVE_TOOL_CONTEXT)
- added debug console to aegis_ai_web
- update to pydantic-ai 1.0.1
- added github mcp tool (https://github.com/github/github-mcp-server)
- added wikipedia mcp tool (https://github.com/rudra-ravi/wikipedia-mcp)
- added pypi mcp tool (https://github.com/kimasplund/mcp-pypi)
- added osv-dev tool (https://osv.dev)

### Changed
- use pydantic-ai toolsets and register MCP in aegis_ai.toolsets 
- ensure suggest-impact uses CVSS3 validation
- update to pydantic-ai 0.4.11
- update to osidb-bindings 4.14.0
- cleaned up settings aegis_ai app settings (~/.config/aegis_ai)
- osv.dev tool is not the main default public agent cve tool


## [0.2.5] - 2025-07-29

### Added
- added AI disclaimer to all responses
- added minimal OTEL support
- enable nvd-mcp tool (requires NVD_API_KEY to be set)

### Changed
- removed a lot of stale code
- refactored aegis_ai_web REST API endpoints
- updated to pydantic-ai 0.4.8
- refactored chat app

### Fixed
- made suggest-cwe more accurate


## [0.2.4] - 2025-07-26

### Added
- Test aegis-ai publishing to pypi


## [0.2.3] - 2025-07-26

### Added
- Initial aegis-ai development release
