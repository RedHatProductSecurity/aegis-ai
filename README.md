# <img src="docs/logo.png" alt="logo" width="50"> Aegis-AI - Red Hat Product Security Agent

[![Aegis Tests](https://github.com/RedHatProductSecurity/aegis/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatProductSecurity/aegis/actions/workflows/tests.yml)

**Note: As Aegis is an agent - be careful of which LLM model you use ... if you want to integrate with OSIDB/RHTPA, you MUST use a secure model**

## Overview

**Aegis enables security teams to leverage the latest Generative AI models for enhanced security analysis.** Integrate your preferred LLM (ChatGPT, Anthropic, Gemini, or even a local model) to quickly perform deep security analysis on critical artifacts like **CVEs, advisories, and more**.

Aegis helps by:

* **Accelerate Analysis:** Insights into complex security data.
* **Improve Accuracy:** Augment LLM capabilities with in-context security information.
* **Enhance Efficiency:** Automate repetitive analysis tasks, working on security entities (ex. CVE) to focus on higher-value work.

---

## Features
Aegis features provide common product security analysis:

### CVE Analysis
* **Suggest Impact:** Get an in context LLM-driven suggestion for a CVE's overall impact.
* **Suggest CWE:** Get an in context LLM-driven Common Weakness Enumeration (CWE) mappings for CVE.
* **Suggest CVSS:** Get an in context LLM-driven Common Vulnerability Scoring System (CVSS) score.
* **Identify PII:** Automatically detect and flag Personally Identifiable Information within security texts.
* **Rewrite Security Text:** Rephrase or refine security advisories and descriptions for clarity or specific audiences.
* **CVSS Diff Explainer:** Understand  differences between Red Hat and NVD CVSS scores with AI-generated explanations.

### Component Intelligence
* **Component Intelligence:** Generate a component information 'card'.

## Security Context
Feature analysis requires 'context' beyond that contained by any specific LLM model. 

We provide 'out of the box' integrations providing security context with the following:

* [OSIDB](https://github.com/RedHatProductSecurity/osidb) 
* [RHTPAv2](https://github.com/trustification/trustify)
* [osv.dev](https://osv.dev)
* CWE (https://cwe.mitre.org)

which perform lookups on security entities (ex. CVE).

Aegis is also a [MCP](https://modelcontextprotocol.io/introduction) client allowing it to easily integrate with any compliant MCP server.

---

## Quick Start

Clone this repo 

or install via [pypi](https://pypi.org/project/aegis-ai/):

```commandline
pip install aegis-ai
```


First ensure `Aegis` can use any required ca certs:
```commandline
REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"
```

### Connecting to LLMs

Aegis allows you to connect to various LLM providers, from your own custom LLM models to cloud LLM services and MaaS.

**Using Aegis with Gemini:**
Connect to Gemini (replace `YOUR_GEMINI_API_KEY` with your actual key):

```bash
AEGIS_LLM_HOST="https://generativelanguage.googleapis.com"
AEGIS_LLM_MODEL="gemini-2.5-flash"
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
````

**Using Aegis with Anthropic:**
Connect to Anthropic's powerful Claude models (replace `YOUR_ANTHROPIC_API_KEY` with your actual key):

```bash
export AEGIS_LLM_HOST="https://api.anthropic.com"
export AEGIS_LLM_MODEL="anthropic:claude-3-5-sonnet-latest"
export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"
```

**Using Aegis with Local Ollama:**
Configure Aegis to use a locally running Ollama instance:

```bash
export AEGIS_LLM_HOST=http://localhost:11434
export AEGIS_LLM_MODEL=llama3.2:3b
# Ensure Ollama is running and 'llama3.2:3b' model is pulled
```

**Note:** For other LLM providers (e.g., OpenAI), similar environment variables will have to set. Refer to the `DEVELOP.md` for environment var information.

Be aware that `Aegis` is an agent (which autonomously invokes tools) so any LLM model you use must be secure/trusted.

### Setting up Aegis Tools

Aegis provides a few 'out of the box' tools that the agent can use to enhance LLM query context.

#### Public tools

##### NVD
Integration with [NVD](https://nvd.nist.gov/vuln) for looking up NIST CVE:
```bash
export AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT=true
export NVD_API_KEY="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXx"
```

##### Github
Integration with [github](https://github.com/):
```bash
export AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT=true
export GITHUB_PERSONAL_ACCESS_TOKEN=
```

##### Tavily Search engine
Integration with [Tavily](https://www.tavily.com/) via built in pydantic-ai support:
```bash
export TAVILY_API_KEY="tvly-dev-XXXXXX"
export AEGIS_USE_TAVILY_TOOL_CONTEXT=true
```

##### Linux cves
Integration with [linux cves repo](https://git.kernel.org/pub/scm/linux/security/vulns.git):
```bash
export AEGIS_USE_LINUX_CVE_TOOL_CONTEXT=true
```
##### Mitre CWE
Integration with [Mitre CWE definitions](https://cwe.mitre.org/data/downloads.html)
```bash
export AEGIS_USE_CWE_TOOL_CONTEXT=true
```
##### Wikipedia
Integration with [wikipedia](https://www.wikipedia.org/):
```bash
export AEGIS_USE_WIKIPEDIA_MCP_CONTEXT=true
```
##### pypi
Integration with [pypi](https://pypi.org/):
```bash
export AEGIS_USE_PYPI_MCP_CONTEXT=true
```
##### DBPedia
Integration with [dbpedia](https://www.dbpedia.org/):
```bash
export AEGIS_USE_DBPEDIA_TOOL_CONTEXT=true
```

##### CISA Kev
Integration with [cisa-kev](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
```bash
export AEGIS_USE_CISA_KEV_TOOL_CONTEXT=true
```

#### RedHat tools

##### OSIDB
Integration with [OSIDB](https://github.com/RedHatProductSecurity/osidb) is achieved via [osidb-bindings](https://github.com/RedHatProductSecurity/osidb-bindings), set
OSIDB server url for Aegis with:
```bash
export AEGIS_OSIDB_SERVER_URL="https://localhost:8080"
```

Uses kerberos built in auth with `osidb-bindings`.

##### RHTPA
TBA

---

## Using Aegis Features
`Aegis` features can be invoked programmatically via Python, through its built-in Command-Line Interface (CLI), or exposed via a REST API.

### Command-Line Interface (CLI)
Run features directly from your terminal using the CLI:

```bash
uv run aegis suggest-impact "CVE-2025-5399"
```

If you installed aegis-ai with pypi, there is no need to use uv:
```commandline
aegis suggest-impact "CVE-2025-5399" 
```

### Programmatic Usage (Python)
If you installed with pypi all dependencies should be installed.

Otherwise if you cloned the repo you must ensure required dependencies are installed before running code example:

```commandline
uv sync 
```

The following programmatically invokes the `SuggestImpact` feature:
```python
import asyncio
from aegis_ai.agents import rh_feature_agent
from aegis_ai.features import cve


async def main():
    feature = cve.SuggestImpact(rh_feature_agent)
    result = await feature.exec("CVE-2025-0725")
    print(result.output.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())
```

Which produces JSON output:

```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 1.0,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "components": [
        "libcurl"
    ],
    "affected_products": [
        "Ansible Services",
        "Hosted OpenShift",
        "cloud.redhat.com"
    ],
    "explanation": "The vulnerability is a buffer overflow within libcurl that occurs during the automatic decompression of gzip-encoded content. 
       However, this flaw is only exploitable when libcurl is used in conjunction with a significantly outdated version of the zlib 
       library (1.2.0.3 or older). Supported Red Hat products, including Red Hat Enterprise Linux, utilize modern versions of zlib and
        are therefore not affected. The impact is rated as LOW because the conditions required for a successful exploit are highly 
        unlikely to be present in any supported Red Hat environment. The official Red Hat CVSS vector indicates a low-impact, local 
        availability issue, reflecting the minimal practical risk.",
    "impact": "LOW",
    "cvss3_score": "3.3",
    "cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cvss4_score": "3.7",
    "cvss4_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"
}

```

Note - Many features, like `SuggestImpact`, require access to an OSIDB server so you will need to be `kinited` in with appropriate access rights.

### REST API Server
You can also accesss the `fastapi` based REST API server:

```bash
uv run uvicorn src.aegis_restapi.src.main:app --port 9000
```

Once running - interact with the API via HTTP - for example: `http://localhost:9000`. 

---
## System Overview
System context diagram for Aegis.

```mermaid
C4Context
    title Aegis System Context Diagram

    System(osim, "OSIM", "Open Source Impact Management (Internal Red Hat System)")
    Person(psirt_analyst, "Stressed out PSIRT Analyst", "The primary user of the Aegis System, needing assistance with vulnerability management.")

    Rel(psirt_analyst, osim, "Retrieves CVE data from", "API")


    Boundary(aegis_system_boundary, "Aegis System") {
        System(osidb, "OSIDB Tool", "OSIDB tool")
        System(aegis, "Aegis", "Aegis agent")
        System(rhtpav2, "RHTPAv2 Tool", "RHTPA tool")
        System(rh_prodsec_kb, "Aegis Knowledgebase", "internal RAG Source")
        System(mcp_servers, "MCP Server(s)", "Managed Cluster Platform Servers (Source of incident data)")
    }

    Boundary(LLM_model, "LLM Model") {
        System(custom_model, "Custom Model", "for secure analysis")
        System(gemini, "gemini")
        System(ollama, "ollama")
        System(chatgpt, "chatgpt")
        System(anthropic, "anthropic")
    }
    
    Rel(osim, aegis, "feature analysis", "API")
    Rel(aegis, custom_model, "LLM inference", "API")

    Rel(aegis, osidb, "fetch CVE", "API")
    Rel(aegis, rhtpav2, "", "API")
    Rel(aegis, rh_prodsec_kb, "", "API")
    Rel(aegis, mcp_servers, "", "API")

```

## Features

### Rewrite Description

```commandline
aegis rewrite-description cve-2025-0725
```
or 

```
GET api/v2/analysis/cve?feature=rewrite-description&cve_id=CVE-2025-0725
```

```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 1.0,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "original_title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "original_description": "A flaw was found in libcurl. This vulnerability allows an attacker to trigger a buffer overflow via an integer overflow in zlib 1.2.0.3 or older when libcurl performs automatic gzip decompression.",
    "components": [
        "libcurl"
    ],
    "explanation": "The original title was slightly long and included implementation details (zlib). The rewritten title is more concise, focusing on the component and the direct vulnerability type. The original description was clear but a bit verbose. The rewritten description is more direct, specifying the attack vector (malicious HTTP response) and clarifying the conditions (automatic gzip decompression with old zlib) in a more streamlined manner, adhering to the structured format.",
    "rewritten_title": "libcurl: gzip decompression buffer overflow",
    "rewritten_description": "A flaw was found in libcurl. This vulnerability allows a remote attacker to cause a buffer overflow via a specially crafted gzip-compressed HTTP response when automatic decompression is enabled with an older version of zlib."
}

```

### Rewrite Statement

```commandline
aegis rewrite-statement cve-2025-0725
```
or
```
GET api/v2/analysis/cve?feature=rewrite-statement&cve_id=CVE-2025-0725
```

```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 0.95,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "components": [
        "netshoot",
        "ocm/golangci-lint",
        "ocm/ocm-acceptance-tests",
        "ocm/selenium-standalone-chrome-debug",
        "ocm/selenium-standalone-firefox-debug",
        "rhsm/wiremock"
    ],
    "statement": [
        "This CVE is not applicable to any supported version of Red Hat Enterprise Linux since RHEL-4."
    ],
    "explanation": "The original statement was factually correct for Red Hat Enterprise Linux (RHEL) but incomplete, as it failed to mention other affected Red Hat products. The rewritten statement provides a more comprehensive view by clarifying the specific condition for the vulnerability (dependency on an old zlib version), explaining why RHEL is not affected, and acknowledging that other Red Hat services are impacted. This approach offers a clearer and more complete picture for all customers.",
    "description": "A flaw was found in libcurl. This vulnerability allows an attacker to trigger a buffer overflow via an integer overflow in zlib 1.2.0.3 or older when libcurl performs automatic gzip decompression.",
    "rewritten_statement": "This flaw is only exploitable when libcurl uses zlib version 1.2.0.3 or older for gzip decompression. Supported versions of Red Hat Enterprise Linux are not affected as they ship with newer versions of the zlib library. Some Red Hat services that bundle older third-party tools may be affected."
}

```

### Suggest Impact

```commandline
aegis suggest-impact CVE-2025-0725
```
or 
```
GET api/v2/analysis/cve?feature=suggest-impact&cve_id=CVE-2025-0725
```
```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 1.0,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "components": [
        "libcurl"
    ],
    "affected_products": [
        "Ansible Services",
        "Hosted OpenShift",
        "cloud.redhat.com"
    ],
    "explanation": "The vulnerability is a buffer overflow within libcurl that occurs during the automatic decompression of gzip-encoded content. 
       However, this flaw is only exploitable when libcurl is used in conjunction with a significantly outdated version of the zlib 
       library (1.2.0.3 or older). Supported Red Hat products, including Red Hat Enterprise Linux, utilize modern versions of zlib and
        are therefore not affected. The impact is rated as LOW because the conditions required for a successful exploit are highly 
        unlikely to be present in any supported Red Hat environment. The official Red Hat CVSS vector indicates a low-impact, local 
        availability issue, reflecting the minimal practical risk.",
    "impact": "LOW",
    "cvss3_score": "3.3",
    "cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cvss4_score": "3.7",
    "cvss4_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"
}
```

### Suggest CWE

```commandline
aegis suggest-cwe cve-2025-0725
```
or
```commandline
GET api/v2/analysis/cve?feature=suggest-cwe&cve_id=CVE-2025-0725
```

```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 0.95,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "components": [
        "libcurl",
        "zlib"
    ],
    "explanation": "The CVE description and title explicitly state that an integer overflow in the zlib library leads to a buffer overflow in libcurl when handling gzip-compressed HTTP responses. CWE-680, which describes an \"Integer Overflow to Buffer Overflow\" scenario, is the most precise and specific identifier for this vulnerability. It accurately captures the complete cause-and-effect chain of the flaw, where the initial integer error is the direct cause of the subsequent buffer overflow.",
    "cwe": [
        "CWE-680"
    ]
}
```

### Identify PII

```commandline
aegis identify-pii cve-2025-0725
```
or
```
GET api/v2/analysis/cve?feature=identify-pii&cve_id=CVE-2025-0725
```

```json
{
    "confidence": 1.0,
    "completeness": 1.0,
    "consistency": 1.0,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "components": [
        "libcurl"
    ],
    "explanation": "",
    "contains_PII": false
}
```

### Explain CVSS diff

```commandline
aegis cvss-diff cve-2025-0725
```
or
```
GET api/v2/analysis/cve?feature=cvss-diff&cve_id=CVE-2025-0725
```

```json
{
    "confidence": 0.95,
    "completeness": 1.0,
    "consistency": 0.95,
    "tools_used": [
        "osidb_tool"
    ],
    "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
    "cve_id": "CVE-2025-0725",
    "title": "Buffer Overflow in libcurl via zlib Integer Overflow",
    "redhat_cvss3_score": "3.3",
    "redhat_cvss3_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "nvd_cvss3_score": "7.3",
    "nvd_cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "components": [
        "libcurl"
    ],
    "affected_products": [
        "Ansible Services",
        "Hosted OpenShift",
        "cloud.redhat.com"
    ],
    "statement": "This CVE is not applicable to any supported version of Red Hat Enterprise Linux since RHEL-4.",
    "explanation": "The Red Hat CVSS3 score is 3.3 (Low), while the NVD CVSS3 score is 7.3 (High). The primary reason for this difference lies in the assessment of the Attack Vector (AV), Confidentiality (C), and Integrity (I) metrics.\n\nRed Hat assigns an Attack Vector of Local (AV:L), based on the specific context of its products. The vulnerability requires an outdated version of the zlib library (1.2.0.3 or older), which is not present in a remotely exploitable manner in supported Red Hat products. Consequently, Red Hat also assesses the impact on Confidentiality and Integrity as None (C:N, I:N), viewing the only potential impact as a local denial of service (Availability: Low).\n\nIn contrast, NVD provides a more generic assessment, rating the Attack Vector as Network (AV:N). This assumes a general use case where the vulnerable libcurl component could be exposed to network-based attacks. This broader perspective leads NVD to assign Low impacts to Confidentiality (C:L) and Integrity (I:L), resulting in a significantly higher overall score. Red Hat's scoring reflects the specific, mitigated risk within its own software ecosystem."
}

```

### Component Intelligence

```commandline
aegis component-intelligence "libcap"
```
or
```
GET api/v2/analysis/component?feature=component-intelligence&component_name=libcap
```

```json
{
  "confidence": 0.95,
  "completeness": 1.0,
  "consistency": 0.95,
  "tools_used": [],
  "disclaimer": "This response was generated by Aegis AI (https://github.com/RedHatProductSecurity/aegis-ai) using generative AI for informational purposes. All findings should be validated by a human expert.",
  "component_name": "libcap",
  "component_latest_version": "2.69",
  "component_purl": "pkg:rpm/redhat/libcap@2.69?arch=x86_64",
  "website_url": "https://sites.google.com/site/fullycapable/",
  "repo_url": "https://git.kernel.org/pub/scm/libs/libcap/libcap.git",
  "popularity_score": 2,
  "stability_score": 2,
  "recent_news": "- January 2024: libcap 2.69 released with minor improvements and bug fixes\n- October 2023: 
Integration with newer kernel capabilities\n- Security patches addressing potential privilege escalation issues in 
2023",
  "active_contributors": "- Andrew G. Morgan (Google) - Primary maintainer\n- Serge Hallyn (Cisco) - Major 
contributor\n- Christian Kastner (Debian) - Regular contributor\n- James Morris (Red Hat) - Kernel capabilities 
maintainer",
  "security_information": "- Total CVEs: 4 historically reported\n- Known exploits: 1 (privilege escalation, 
patched)\n- Critical security focus on capability handling and privilege management\n- Regular security audits due to 
its role in Linux security\n- Included in Red Hat Enterprise Linux security framework\n- No PII data exposure in CVE 
records",
  "further_learning": "- Official documentation: https://sites.google.com/site/fullycapable/\n- Linux capabilities 
manual: https://man7.org/linux/man-pages/man7/capabilities.7.html\n- Red Hat Enterprise Linux Security Guide: 
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index\n- Kernel.org 
documentation: https://www.kernel.org/doc/html/latest/admin-guide/capabilities.html",
  "explanation": "Libcap is a fundamental Linux library that implements POSIX capabilities, crucial for fine-grained 
privilege control in Linux systems. As a core security component in Red Hat Enterprise Linux and other major 
distributions, it maintains high stability and popularity scores. The project shows consistent maintenance, regular 
updates, and strong security practices. The analysis confidence is high due to the project's public nature, 
well-documented history, and clear maintenance patterns.",
}
```
