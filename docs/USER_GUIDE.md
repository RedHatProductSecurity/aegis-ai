# Aegis AI - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [AI Functionality Notice](#ai-functionality-notice)
3. [Getting Started](#getting-started)
4. [Installation and Deployment](#installation-and-deployment)
5. [Configuration](#configuration)
6. [Administration](#administration)
7. [Contact and Support](#contact-and-support)
8. [Best Practices and Compliant Use](#best-practices-and-compliant-use)
9. [Sample Prompts and Use Cases](#sample-prompts-and-use-cases)
10. [Recommended Data Inputs](#recommended-data-inputs)
11. [Important Disclaimers](#important-disclaimers)
12. [Quick Reference](#quick-reference)

---

## Introduction

**Aegis AI** is an AI-powered security analysis tool designed to assist Product Security Incident Response Teams (PSIRT) and security analysts in analyzing security artifacts such as CVEs, advisories, and software components. Aegis leverages Large Language Models (LLMs) to provide intelligent suggestions and automate repetitive security analysis tasks.

### What Aegis Does

Aegis helps security teams by:

- **Accelerating Analysis:** Providing rapid insights into complex security data
- **Improving Accuracy:** Augmenting LLM capabilities with in-context security information from trusted sources
- **Enhancing Efficiency:** Automating repetitive analysis tasks to allow focus on higher-value work

### Key Capabilities

Aegis provides specialized features for:

- CVE impact assessment and CVSS scoring
- CWE (Common Weakness Enumeration) identification
- Security text generation and refinement
- PII (Personally Identifiable Information) detection
- Component intelligence gathering
- CVSS score difference explanations

---

## AI Functionality Notice

**IMPORTANT:** Aegis uses **Generative AI (Large Language Models)** to perform security analysis. This means:

- All analysis results are **AI-generated suggestions** that require human expert review
- The AI models used may include cloud-based services (e.g., Gemini, Anthropic Claude, OpenAI) or local models (e.g., Ollama)
- AI responses are probabilistic and may vary between runs
- The tool autonomously invokes external tools and data sources to gather context
- **You must use a secure, trusted LLM model** when working with sensitive or embargoed data

### How AI is Used in Aegis

Aegis uses AI in the following ways:

1. **Autonomous Agents:** AI agents autonomously decide when and how to use available tools to gather context
2. **Context Enrichment:** AI retrieves relevant information from security databases (OSIDB, NVD, CWE, etc.)
3. **Analysis Generation:** AI generates suggestions, explanations, and assessments based on the gathered context
4. **Natural Language Processing:** AI processes and understands security-related text to provide structured outputs

Learn more in about [how Aegis works here](TRANSPARENCY.md).

---

## Getting Started

### Quick Start

```bash
# Install Aegis
pip install aegis-ai

# Configure LLM
export AEGIS_LLM_HOST="https://generativelanguage.googleapis.com"
export AEGIS_LLM_MODEL="gemini-2.5-flash"
export GEMINI_API_KEY="YOUR_API_KEY"

# Run your first analysis
aegis suggest-impact "CVE-2025-0725"
```

### Basic Configuration

Before using Aegis, you need to configure environment variables that include your LLM provider, network connections/certificates, and other settings that affect how Aegis processes data. See the [Configuration Reference](env-vars.md) for detailed environment variable settings.

---

## Installation and Deployment

### System Requirements

- **Python:** 3.13 (see `pyproject.toml` for exact version requirements)
- **Package Manager:** `uv` (recommended) or `pip`
- **Container Runtime:** Podman (for MCP server tools, optional)
- **Memory:** Minimum 4GB RAM (8GB+ recommended)

### Installation Methods

#### Method 1: PyPI Installation

```bash
pip install aegis-ai
```

#### Method 2: Source Installation

```bash
git clone https://github.com/RedHatProductSecurity/aegis-ai.git
cd aegis-ai
uv sync  # or: pip install -e .
```

### Deployment Options

#### Option 1: CLI Tool

Install as a command-line tool for individual users:

```bash
pip install aegis-ai
# Users can then run: aegis <command>
```

#### Option 2: REST API Service

Deploy as a web service using FastAPI:

```bash
pip install aegis-ai[web]
uvicorn src.aegis_ai_web.src.main:app --host 0.0.0.0 --port 9000
```

#### Option 3: Container Build

Build using the provided Containerfile:

```bash
podman build -f Containerfile -t aegis-ai:latest .
podman run -p 9000:9000 aegis-ai:latest
```

---

## Configuration

### Environment Variables

Aegis is configured primarily through environment variables. See [env-vars.md](env-vars.md) for a complete reference.

### Essential Configuration

```bash
# LLM Provider Settings
export AEGIS_LLM_HOST="https://generativelanguage.googleapis.com"
export AEGIS_LLM_MODEL="gemini-2.5-flash"
export GEMINI_API_KEY="your-api-key-here"

# CA Certificates (if needed)
export REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
```

### Configuration Files

Aegis can use `.env` files for configuration. Create a `.env` file in the working directory:

```bash
AEGIS_LLM_HOST=https://generativelanguage.googleapis.com
AEGIS_LLM_MODEL=gemini-2.5-flash
GEMINI_API_KEY=your-key-here
AEGIS_OSIDB_SERVER_URL=https://osidb.example.com
```

### Agent Profiles

Aegis supports different agent profiles:

- **Public Profile:** Uses public tools and data sources (default)
- **Red Hat Profile:** Uses Red Hat internal tools (OSIDB, RHTPA)

```bash
# For CLI
export AEGIS_CLI_FEATURE_AGENT="redhat"  # or "public"

# For Web API
export AEGIS_WEB_FEATURE_AGENT="redhat"  # or "public"
```

> **⚠️ Embargoed Data:** The Red Hat profile has access to OSIDB which may contain embargoed CVEs. External tools (Wikipedia, GitHub, Tavily) are disabled by default to prevent data leakage. Embargoed CVE retrieval is also blocked by default (`AEGIS_OSIDB_RETRIEVE_EMBARGOED=false`). See [TRANSPARENCY.md](TRANSPARENCY.md) for details.

### Toolset Configuration

Aegis uses a layered toolset system with security-first defaults, which introduces some complexity to toolset configuration.
The complexity primarily comes from:
1. Security-first defaults requiring explicit opt-in for external tools
2. Differing tool types with varying boundaries (native Python functions, network communication with MCP subprocess servers)
3. Varied authentication (API keys, Kerberos)
4. Runtime infrastructure requirements for container/MCP tools 

**Toolset Categories:**

| Toolset | Purpose | Default |
|---------|---------|---------|
| `public_toolset` | General-purpose tools (CWE, Wikipedia, GitHub, etc.) | Conditional per tool |
| `redhat_cve_toolset` | Red Hat-specific CVE tools (OSIDB) | Always on for `redhat` profile |
| `public_cve_toolset` | Public CVE tools (OSV.dev, NVD) | OSV always, NVD conditional |

**Tool Enable/Disable Requirements:**

| Tool | Enable Flag | Additional Requirements |
|------|-------------|------------------------|
| CWE | `AEGIS_USE_CWE_TOOL_CONTEXT=true` ✅ | None |
| CISA KEV | `AEGIS_USE_CISA_KEV_TOOL_CONTEXT=false` | None |
| Linux CVE | `AEGIS_USE_LINUX_CVE_TOOL_CONTEXT=false` | None |
| Wikipedia | `AEGIS_USE_WIKIPEDIA_TOOL_CONTEXT=false` | None |
| Wikipedia MCP | `AEGIS_USE_WIKIPEDIA_MCP_CONTEXT=false` | `uv` installed |
| GitHub MCP | `AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT=false` | `GITHUB_PERSONAL_ACCESS_TOKEN`, `podman` |
| PyPI MCP | `AEGIS_USE_PYPI_MCP_CONTEXT=false` | `uv` installed |
| NVD MCP | `AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT=false` | `NVD_API_KEY`, `uv` installed |
| Tavily | `AEGIS_USE_TAVILY_TOOL_CONTEXT=false` | `TAVILY_API_KEY` |
| OSIDB (embargoed) | `AEGIS_OSIDB_RETRIEVE_EMBARGOED=false` | Kerberos auth, network access |

**Security-First Defaults:**

Most external tools are disabled by default to prevent embargoed data leakage:

- **External tools (default OFF):** Wikipedia, GitHub MCP, Tavily, PyPI — could leak CVE context to third parties
- **OSIDB embargoed retrieval (default OFF):** Explicit opt-in required for sensitive data
- **Internal/Safe tools (default ON):** CWE tool — local data, no external calls

**Runtime Dependencies for MCP Tools:**

MCP-based tools require additional infrastructure:

- **GitHub MCP:** Requires `podman` and container image (`mcp/github-mcp-server`)
- **Wikipedia/PyPI/NVD MCP:** Requires `uv` package manager installed
- All MCP tools spawn subprocess servers via `MCPServerStdio`

### LLM Provider Setup

#### Google Gemini

```bash
export AEGIS_LLM_HOST="https://generativelanguage.googleapis.com"
export AEGIS_LLM_MODEL="gemini-2.5-flash"
export GEMINI_API_KEY="your-api-key"
```

Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey).

#### Anthropic Claude

```bash
export AEGIS_LLM_HOST="https://api.anthropic.com"
export AEGIS_LLM_MODEL="anthropic:claude-3-5-sonnet-latest"
export ANTHROPIC_API_KEY="your-api-key"
```

#### Local Ollama

```bash
ollama pull llama3.2:3b
export AEGIS_LLM_HOST="http://localhost:11434"
export AEGIS_LLM_MODEL="llama3.2:3b"
```

#### OpenAI (ChatGPT)

```bash
export AEGIS_LLM_HOST="https://api.openai.com/v1"
export AEGIS_LLM_MODEL="openai:gpt-4"
export OPENAI_API_KEY="your-api-key"
```

### Security Considerations for LLM Selection

| Data Classification | Recommended Model Type |
|---------------------|------------------------|
| Public CVE data | Public cloud LLM (Gemini, Claude, ChatGPT) |
| Internal/Embargoed CVEs | Enterprise/Private LLM or Local model |
| Classified data | Local model only |

---

## Administration

### Security Configuration

#### API Key Management

1. **Never commit API keys to version control**
2. Use environment variables or secure secret management
3. Rotate keys regularly
4. Use separate keys for different environments

#### Network Security

1. **TLS/SSL:** Ensure all external connections use HTTPS
2. **Firewall Rules:** Restrict access to exposed ports
3. **VPN/Private Networks:** Use for internal tool access

### Authentication

#### OSIDB Integration

```bash
export AEGIS_OSIDB_SERVER_URL="https://osidb.example.com"
kinit user@REALM  # Kerberos authentication
```

#### Web API Authentication

```bash
export AEGIS_WEB_SPN="HTTP/aegis.example.com@REALM"
export KRB5_KTNAME="/etc/krb5.keytab"
```

### Monitoring and Logging

#### Logging Configuration

```bash
export AEGIS_LOG_FILE="/var/log/aegis/aegis.log"
```

#### OpenTelemetry Integration

```bash
export AEGIS_OTEL_ENABLED="true"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317"
```

#### KPI Endpoint

```bash
curl "http://localhost:9000/api/v2/analysis/kpi/cve?feature=suggest-impact"
curl "http://localhost:9000/api/v2/analysis/kpi/cve?feature=all"
```

### Feedback Management

Configure feedback logging:

```bash
export AEGIS_WEB_FEEDBACK_LOG="/var/log/aegis/feedback.csv"
```

Process feedback:

```bash
python scripts/process_cve_feedback_form.py /path/to/feedback.csv
```

### Troubleshooting

#### LLM Connection Failures

- Verify API keys are correct and not expired
- Check network connectivity to LLM provider
- Verify firewall/proxy settings

#### OSIDB Authentication Failures

- Verify Kerberos ticket is valid: `klist`
- Renew ticket: `kinit user@REALM`
- Check OSIDB server URL is correct

#### Tool Context Not Available

- Verify required environment variables are set
- Check tool-specific API keys are configured
- Review tool enablement flags (e.g., `AEGIS_USE_CWE_TOOL_CONTEXT`)

### Maintenance

1. **Update Aegis:** `pip install --upgrade aegis-ai`
2. **Update Dependencies:** `uv sync --upgrade`
3. **Review Logs:** Regularly review application and feedback logs
4. **Monitor Costs:** Track LLM API usage and costs
5. **Security Updates:** Apply security patches promptly

---

## Contact and Support

**Slack:** Contact the Aegis team on Slack 

**GitHub Issues:** [https://github.com/RedHatProductSecurity/aegis-ai/issues](https://github.com/RedHatProductSecurity/aegis-ai/issues)

---

## Best Practices and Compliant Use

### General Best Practices

1. **Always Review AI Outputs:** Never use AI-generated results without human expert review
2. **Verify Against Sources:** Cross-reference AI suggestions with authoritative security databases
3. **Understand Context:** Ensure you understand what context the AI used to generate its response
4. **Check Confidence Scores:** Pay attention to confidence scores - lower scores may indicate uncertainty
5. **Use Appropriate Models:** For sensitive data, use secure, trusted LLM models (not public cloud services)
6. **Validate Tool Usage:** Review which tools the AI used to gather context (check `tools_used` field)

### Security and Compliance

1. **Data Handling:**
   - Do not submit classified, embargoed, or highly sensitive data to public cloud LLM services
   - Use local or secure enterprise LLM models for sensitive analysis
   - Be aware of data retention policies of your LLM provider

2. **Access Control:**
   - Ensure proper authentication when connecting to OSIDB or other internal systems
   - Use Kerberos authentication for Red Hat internal tools
   - Protect API keys and credentials

3. **Audit and Logging:**
   - Review feedback logs regularly
   - Monitor tool usage patterns
   - Keep records of AI-assisted decisions

### Workflow Integration

1. **Use as a Starting Point:** Treat AI suggestions as initial assessments, not final decisions
2. **Iterative Refinement:** Use feedback mechanisms to improve suggestions over time
3. **Document Decisions:** Record why you accepted or rejected AI suggestions
4. **Team Collaboration:** Share feedback with your team to improve collective understanding

---

## Sample Prompts and Use Cases

### Use Case 1: Initial CVE Impact Assessment

**Command:**
```bash
aegis suggest-impact "CVE-2025-0725"
```

**Expected Output:** Impact level, CVSS scores, affected products, explanation of the assessment.

**Best Practice:** Use this as a triage tool to prioritize CVEs for detailed analysis.

### Use Case 2: CWE Identification

**Command:**
```bash
aegis suggest-cwe "CVE-2025-0725"
```

**Expected Output:** List of applicable CWE identifiers with explanation.

**Best Practice:** Review the generated explanation to ensure the CWE mapping is accurate for your context.

### Use Case 3: Security Text Generation

**Command:**
```bash
aegis suggest-description "CVE-2025-0725"
```

**Expected Output:** Suggested title/description with explanation.

**Best Practice:** Adapt suggested text based on your audience needs.

### Use Case 4: PII Detection

**Command:**
```bash
aegis identify-pii "CVE-2025-0725"
```

**Expected Output:** Boolean flag indicating PII presence with explanation.

**Best Practice:** Always run this check before publishing security advisories publicly.

### Use Case 5: CVSS Score Explanation

**Command:**
```bash
aegis cvss-diff "CVE-2025-0725"
```

**Expected Output:** Both CVSS scores with detailed explanation of differences.

**Best Practice:** Use this to document and communicate scoring rationale to stakeholders.

### Use Case 6: Component Intelligence

**Command:**
```bash
aegis component-intelligence "libcap"
```

**Expected Output:** Component metadata, security information, popularity scores, contributors.

**Best Practice:** Use this to quickly understand component context before security analysis.

### Use Case 7: Statement Generation

**Command:**
```bash
aegis suggest-statement "CVE-2025-0725"
```

**Expected Output:** Suggested statement and mitigation with explanation.

**Best Practice:** Review and customize the statement to match your organization's communication style.

---

## Recommended Data Inputs

### CVE Analysis Features

**Input Requirements:**
- **CVE ID Format:** Must follow standard CVE format: `CVE-YYYY-NNNNN`
- **Valid CVE:** The CVE should exist in security databases (NVD, OSIDB, etc.)
- **Access Rights:** For Red Hat internal features, ensure you have OSIDB access

**Best Inputs:**
- Recent CVEs with available metadata
- CVEs with existing Red Hat analysis (for comparison)
- CVEs affecting well-documented components

**Avoid:**
- Invalid or non-existent CVE IDs
- CVEs with incomplete or missing metadata
- Embargoed CVEs (unless using secure models)

### Component Intelligence

**Input Requirements:**
- **Component Name:** Standard package or library name (e.g., "libcurl", "openssl")
- **Specificity:** More specific names yield better results

**Best Inputs:**
- Well-known open-source components
- Components with public repositories
- Components with existing security documentation

---

## Important Disclaimers

### ⚠️ Human Review Required

**CRITICAL:** All results generated by Aegis AI **MUST** be reviewed and validated by qualified human security experts before use in production systems, security advisories, or decision-making processes.

### AI Limitations

1. **Probabilistic Nature:** AI models generate probabilistic outputs that may vary between runs
2. **Context Dependency:** Results depend on available context and tool access
3. **Potential Errors:** AI may generate incorrect, incomplete, or misleading information
4. **Bias:** AI models may reflect biases present in training data
5. **Hallucination:** AI may generate plausible-sounding but incorrect information

### No Warranty

- Aegis AI is provided "as-is" without warranty of any kind
- Red Hat does not guarantee the accuracy, completeness, or reliability of AI-generated suggestions
- Users are solely responsible for validating all AI outputs
- Red Hat is not liable for decisions made based on AI suggestions

---

## Quick Reference

### CLI Commands

```bash
# CVE Impact Assessment
aegis suggest-impact "CVE-2025-0725"

# CWE Identification
aegis suggest-cwe "CVE-2025-0725"

# Description Refinement
aegis suggest-description "CVE-2025-0725"

# Statement Generation
aegis suggest-statement "CVE-2025-0725"

# PII Detection
aegis identify-pii "CVE-2025-0725"

# CVSS Difference Explanation
aegis cvss-diff "CVE-2025-0725"

# Component Intelligence
aegis component-intelligence "libcap"
```

---

## Additional Resources

- [Transparency Guide](TRANSPARENCY.md) - AI usage transparency and training
- [Configuration Reference](env-vars.md) - Environment variables
- [OpenAPI Specification](openapi.yml) - API documentation
- [Development Guide](../DEVELOP.md) - For developers

---

**Version:** See [CHANGELOG.md](CHANGELOG.md)
