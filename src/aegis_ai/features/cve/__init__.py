import logging
from typing import Any

from aegis_ai.data_models import CVEID
from aegis_ai.features import Feature
from aegis_ai.features.cve.data_models import (
    CVSSDiffExplainerModel,
    SuggestImpactModel,
    SuggestCWEModel,
    PIIReportModel,
    RewriteStatementModel,
    RewriteDescriptionModel,
)
from aegis_ai.features.cve.data_models import CVEFeatureInput
from aegis_ai.prompt import AegisPrompt

logger = logging.getLogger(__name__)


class SuggestImpact(Feature):
    """Based on current CVE information and context assert an aggregated impact."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and assess basic CVSS 3.1 vector/score from the perspective of Red Hat customers.  Based on the CVSS 3.1 score predict the impact (LOW/MODERATE/IMPORTANT/CRITICAL). Ignore existing labels and decide independently.",
            goals="""
                Impact scale (summary):
                - CRITICAL: A remote unauthenticated user can execute arbitrary code. Does not require user interaction.  9.0 < cvss3_score
                - IMPORTANT: Allows local users to gain privileges.  Unauthenticated remote users can view resources.  Authenticated remote users can execute arbitrary code.  7.0 < cvss3_score <= 9.0
                - MODERATE: Harder to exploit or limited scope/conditions.  4.0 < cvss3_score <= 7.0
                - LOW: Unlikely or minimal consequence.  cvss3_score <= 4.0
                Also output a plausible CVSS 3.1 base vector and score.
            """,
            rules="""
                - Consider: basic CVSS 3.1 metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability.
                - User Interaction is Required for an application to connect a malicious server.
                - Denial of Service (DoS) has lower impact on applications compared to daemons and servers.
                - Always use kernel_cve tool to provide additional CVE context when CVE component is kernel.
                - Do not base the decision on which RH products are affected.
                - Provide confidence in [0.00..1.00]. Keep explanations concise.
                - If kernel CVE then use linux_kernel_tool to retrieve more context.
                - if CVE impacts a python module then use mcp-pypi tool to retrieve more context.
                - if cisa_kev_tool tool is available always check if there are any related known exploits.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=SuggestImpactModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=SuggestImpactModel)


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="From the CVE JSON, identify the most specific CWE that matches the root cause. Ignore any pre-labeled CWE.",
            goals="""
                - Use cwe_tool to check canonical CWE definitions.
                - Never return CWEs that are marked as disallowed by the cwe_tool.
                - Prefer the most specific CWE over broad parents.
                - Return a short explanation and confidence.
            """,
            rules="""
                Always use kernel_cve tool to provide additional CVE context if CVE component is kernel.
                Output should include:
                - cwe: a list of 1–3 likely CWE IDs (e.g., ["CWE-125"]).
                - explanation: 1–2 sentences connecting CVE details to the CWE.
                - confidence: [0.00..1.00].
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=SuggestCWEModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=SuggestCWEModel)


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Examine the CVE JSON and identify any PII (names, emails, phone numbers, IDs, IPs, health/genetic info, etc.).",
            goals="""
                - Traverse all fields; consider both keys and values.
                - Prefer precise matches; avoid speculation.
            """,
            rules="""
                Output rules:
                - explanation: If PII is found, provide a bulleted list using the '-' character. Each item must be in the format: PII type: "exact string". Example: - Gender: "male".
                  - The PII type must be a concise description (e.g., "Gender", "Race", "Email Address", "Phone Number").
                  - The "exact string" must be the literal value from the JSON.
                  - Create a new bullet point for each unique instance of PII found.
                  - If no PII is found, this field should be an empty string ("").
                - confidence: [0.00..1.00].
                - contains_PII: true if any PII found, else false.
                
                Only report PII present in the JSON. Do not add extra text or line breaks like \n inside items.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=PIIReportModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=PIIReportModel)


class RewriteDescriptionText(Feature):
    """Based on current CVE information and context rewrite/create description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Rewrite the CVE description and title to be brief, clear, and accurate. If missing, propose them.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
            """,
            rules="""
                Description: one short paragraph of the form:
                "A flaw was found in [component]. This vulnerability allows [impact] via [vector]."
                - No versioning or extra commentary.
                Title: <= 7 words, include product/component and vulnerability type.
                Do not duplicate fields like versions; keep it focused and professional.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=RewriteDescriptionModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=RewriteDescriptionModel)


class RewriteStatementText(Feature):
    """Based on current CVE information and context rewrite/create statement."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Rewrite the CVE statement to briefly explain RH-specific context for impact; leave empty if none.",
            goals="""
                - Clarify why RH impact may differ from industry reports.
                - Provide customer-relevant context only.
            """,
            rules="""
                - Do not duplicate information available in other fields, such as flaw description.
                - Do not include any low-level technical details, such as specific code changes.
                - Do not advise applying patches, rebuilding software, or monitoring for updates.
                - If no additional RH-specific context exists, return an empty statement.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=RewriteStatementModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=RewriteStatementModel)


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Compare Red Hat CVSS3 vs NVD CVSS3 for the CVE and explain any differences.",
            goals="""
                - Report both base vectors/scores.
                - If identical, explanation must be empty.
            """,
            rules="""
                Be specific about which metrics drive the difference (AV, AC, PR, UI, CIA).
                Keep the rationale brief and factual. If no difference, return an empty explanation.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=CVSSDiffExplainerModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=CVSSDiffExplainerModel)
