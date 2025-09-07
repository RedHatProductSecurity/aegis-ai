# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added

### Changed

### Fixed

## [0.2.9] - 2025-09-07

### Added
- added dbpedia tool (https://www.dbpedia.org/)
- added cisa-kev tool (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)


## [0.2.8] - 2025-09-07

### Changed
- update openapi 


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
