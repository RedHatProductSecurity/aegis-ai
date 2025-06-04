# ADR 00001: Aegis - AI-Powered Product Security Analysis

**Date:** 2025-05-23

## Status

Accepted

## Context

Security analysts, particularly those in Product Security Incident Response Teams (PSIRT), face significant challenges in the timely and accurate assessment of security artifacts like CVEs and advisories. Key pain points include:

* **Prediction & Matching:** Accurately determining CVE severity, identifying applicable CWEs, assessing exploitability, etc.
* **Component Intelligence:** Aggregating and understanding information about software components and related development processes.
* **Contextual Explanations:** Providing clear rationales for security assessments (e.g., explaining CVSS differences).
* **Efficient Routing & Triage:** Rapidly categorizing and prioritizing incoming security information.
* **Scalability & Quality:** Consistently delivering high-quality analysis across diverse software ecosystems at scale.

These challenges are well-suited for AI/ML solutions, often requiring a blend of approaches, from generative AI (LLMs) to classical machine learning (SVM, NLP). The rapidly evolving AI landscape necessitates a flexible architecture that supports multiple LLM models and allows for quick adaptation to new techniques, while ensuring stable, accurate, and consistent analysis.

### Requirements

* **AI-Powered Assistance:** Provide PSIRT analysts with AI-based suggestion and automation services to aid in routing, triaging, assessing, and managing high-quality CVE artifacts within their security workflows.
* **Contextual Accuracy:** Ensure high-quality and accurate analysis by providing custom, filtered query context specific to PSIRT needs.
* **Feature Set:** Offer specialized features for suggesting and automating security analysis within a constrained context (e.g., Red Hat product security), including:
    * Suggest CVE CWE-ID.
    * Suggest CVE severity/CVSS.
    * Suggest higher-quality text (e.g., CVE statement, CVE description).
    * Assess CVE exploitability.
    * Assess security artifacts for routing/triage/applicability.
    * Assess false positives (e.g., affected components).
    * Generate component intelligence for specific components.
    * Generate explanations (e.g., differences in CVSS between NVD and Red Hat).
* **Foundational Stability:** Provide a stable and extensible foundation for continuous incremental development, supporting both generative AI and classical ML features.
* **External Integration:** Provide out-of-the-box integration with [MCP](https://modelcontextprotocol.io/introduction) for ad-hoc query context enrichment.
* **Secure Environment:** Ensure the production service operates within an appropriately secure environment, with stringent data filters and no potential for data leakage, especially when handling embargoed CVEs.

## Decision

We will develop a standalone **Aegis Python module** (available at [https://github.com/RedHatProductSecurity/aegis](https://github.com/RedHatProductSecurity/aegis)) comprising:

1.  **Aegis Library:** Core logic integrating with LLMs via the `AEGIS_LLM_HOST` configuration.
2.  **Aegis CLI:** A `click`-based command-line interface for easy management and test interaction.
3.  **Aegis REST API:** A `FastAPI`-based web service as an example integration of Aegis features.

All components of the system are open source.

**Initial Feature Implementation:**
The first features to be delivered will be:
* **Suggest Impact**
* **Suggest CWE-ID**
* TBD

For each feature, responses will be:
* **Well-structured JSON.**
* Include a **confidence score** reflecting Aegis's analysis certainty.
* **Enumerate sources** contributing to the analysis.
* Provide a clear **explanation** of the analysis rationale.

**Integration & Context:**
* Provide UX integration of Aegis features into the [OSIM](https://github.com/RedHatProductSecurity/osim/) UX.
* Integrate [OSIDB](https://github.com/RedHatProductSecurity/osidb/) and [RHTPAv2](https://github.com/trustification/trustify) data sources for custom and private query context enrichment.
* Implement a **GRAPHRAG/RAG solution** knowledgebase starting with [pgvector](https://github.com/pgvector/pgvector) to enable private RAG. This will allow PSIRT analysts to securely upload and use their own documents ("facts") to continuously improve Aegis's analysis.
* Provide out-of-the-box integration with MCP servers for ad-hoc query context enrichment.
* We **MAY** provide an MCP server for Aegis itself so other MCP clients can connect.

**Development & Deployment:**
* Establish clear paths for easy, secure, and "frictionless" development of Agent AI features.
* Ensure clear extensibility paths for incubating new features and ongoing development.
* **Technology Stack:** Aegis will leverage common and popular Python dependencies, including `torch`, `llama-stack`, `pydantic-ai`, `scikit-learn`, `nlp`, `numpy`, and `Hugging Face` modules.
* **Deployment:** Provide clear deployment paths for common infrastructures (e.g., OpenShift AI, vLLM), facilitating scalability, management, and hosting of production instances.

**Quality & Monitoring:**
* **Test Suites:** Implement comprehensive unit tests for the Aegis library, CLI, and REST API, alongside evaluation tests to assert analysis accuracy and quality.
* **Monitoring:** Establish monitoring for performance and continuous evaluation of analysis quality.

## Alternative Approaches

* **Reliance Solely on Third-Party LLM Services (e.g., ChatGPT, Gemini):**
    * **Consequence:** Without providing custom query context from internal systems (OSIDB/OSIM, RHTPAv2), achieving sufficient accuracy with prompt-only development is challenging.
    * **Risk:** Uploading sensitive or embargoed information to external services presents significant data leakage risks and could compromise fine-grained authorization systems by requiring coarser credentials.
    * **Mitigation:** Aegis will support third-party services but prioritize working with custom models (via common API endpoints) to allow selection based on accuracy, cost, and a mix of models for agentic workflows.
* **LangChain instead of `pydantic-ai`:**
    * **Consequence:** [LangChain](https://www.langchain.com/), being an older framework, encapsulates more historical GenAI interfaces and approaches, leading to more "moving parts" compared to `pydantic-ai`.
    * **Decision Rationale:** We prioritize simplicity, which `pydantic-ai` provides, on top of `pydantic` for structured input/output.
* **Full-Blown RAG Frameworks (e.g., Haystack):**
    * **Consequence:** Adopting comprehensive LLM frameworks like [Haystack](https://haystack.deepset.ai/) entails taking on significant architectural "opinions" and potential vendor lock-in.
    * **Decision Rationale:** We prefer a simpler, more Pythonic approach to data and structured I/O (using `pydantic-ai`) as a first step to avoid early lock-in in a rapidly evolving field. Other frameworks can be adopted later if needed.

## Risks & Consequences

* **MCP Integration Maturity:** Current MCP detail on authentication/authorization, scaling, and proxying user credentials for database agent usage is insufficient.
    * **Mitigation:** Initially, we will provide ad-hoc MCP integration limited to common, public MCP resources. Our internal systems (OSIDB/OSIM, RHTPAv2) will have custom, more secure integrations. We will revisit broader MCP interface utilization as experience and MCP maturity grow.
* **GPU Resource Prediction:** Predicting GPU resource usage for concurrent users, fine-tuning, and model serving is challenging.
    * **Mitigation:** Early and continuous load testing will be performed to understand performance under realistic loads.
* **Developer GPU Access:** Developers will require access to GPU resources for efficient feature development.
    * **Mitigation:** Ensure adequate provisioning of development environments with GPU access.
* **Agent AI Security Surface Area:** Agent AI, with its independent/asynchronous LLM-controlled tool calling, introduces new security surface areas.
    * **Mitigation:** Ensure appropriate controls and security measures are in place to mitigate potential risks. This will be a continuous focus during design and implementation.