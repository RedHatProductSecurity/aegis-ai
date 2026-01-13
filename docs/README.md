# Aegis AI Documentation

Welcome to the Aegis AI documentation.

## Quick Links

### For Users

- **[User Guide](USER_GUIDE.md)** - Start here! Comprehensive guide covering:
  - AI functionality and transparency
  - Getting started and configuration
  - Installation and deployment
  - LLM provider setup
  - Best practices and compliant use
  - Sample prompts and use cases
  - Administration and troubleshooting

### Available Features

**CVE Analysis:**
- **Suggest Impact** - AI-driven assessment of a CVE's overall impact on Red Hat products (triage, prioritization)
- **Suggest CWE** - Identifies applicable CWE identifiers for vulnerability taxonomy mapping
- **Suggest Description** - Suggests improvements to CVE titles and descriptions for clarity
- **Suggest Statement** - Generates or improves CVE statements explaining product impact
- **Identify PII** - Detects Personally Identifiable Information in security texts before publication
- **CVSS Diff Explainer** - Explains differences between Red Hat and NVD CVSS scores

**Component Analysis:**
- **Component Intelligence** - Generates comprehensive information about a software component

See the [OpenAPI Specification](openapi.yml) for detailed API documentation including endpoints, request/response schemas, and examples.

### Transparency and Training

- **[Transparency Guide](TRANSPARENCY.md)** - AI usage transparency:
  - How Aegis uses AI
  - Agent architecture and tool selection
  - Data handling and privacy
  - User training requirements
  - Appropriate use guidelines
  - Human review requirements

### Additional Resources

- **[Configuration Reference](env-vars.md)** - Complete environment variable reference
- **[Changelog](CHANGELOG.md)** - Version history
- **[Architecture Decision Records](adrs/)** - Design decisions
- **[OpenAPI Specification](openapi.yml)** - API documentation
- **[OpenTelemetry Guide](otel.md)** - Observability configuration

## Documentation Structure

```
docs/
├── USER_GUIDE.md          # Main user and admin documentation
├── TRANSPARENCY.md         # AI transparency, training, and agent architecture
├── env-vars.md             # Configuration reference
├── CHANGELOG.md            # Version history
├── otel.md                 # OpenTelemetry guide
├── openapi.yml             # API specification (feature details)
└── adrs/                   # Architecture decisions
```

## Getting Started

1. **New Users:** Start with the [User Guide](USER_GUIDE.md)
2. **Understanding AI Usage:** Read the [Transparency Guide](TRANSPARENCY.md)
3. **API Details:** Consult the [OpenAPI Specification](openapi.yml)

## Support

- **Slack:** Contact the Aegis team on Slack 
- **GitHub Issues:** [https://github.com/RedHatProductSecurity/aegis-ai/issues](https://github.com/RedHatProductSecurity/aegis-ai/issues)
- **Feedback:** Submit via `/api/v1/feedback` endpoint

## Important Reminders

⚠️ **All AI-generated outputs require human expert review before use.**

- Review the [Transparency Guide](TRANSPARENCY.md) to understand AI usage
- Follow [best practices](USER_GUIDE.md#best-practices-and-compliant-use) for compliant use

