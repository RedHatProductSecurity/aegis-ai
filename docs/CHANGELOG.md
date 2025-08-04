# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- added cwe_tool
- added /openapi.yml 
- added `make check-type`

### Changed
- use pydantic-ai toolsets and register MCP in aegis_ai.toolsets 
- ensure suggest-impact uses CVSS3 validation
- update to pydantic-ai 0.4.11
- update to osidb-bindings 4.14.0
- cleaned up settings aegis_ai app settings (~/.config/aegis_ai)

### Fixed

## [0.2.45 - 2025-29-07
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

## [0.2.4] - 2025-26-07
### Added
- Test aegis-ai publishing to pypi

## [0.2.3] - 2025-26-07
### Added
- Initial aegis-ai development release

