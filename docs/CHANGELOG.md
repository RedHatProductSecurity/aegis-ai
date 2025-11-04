# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
