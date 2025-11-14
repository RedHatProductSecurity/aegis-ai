import cvss
import logging
from typing import Any

from aegis_ai.data_models import CVEID
from aegis_ai.features import Feature
from aegis_ai.features.cve.data_models import (
    CVSSDiffExplainerModel,
    SuggestImpactModel,
    SuggestCWEModel,
    PIIReportModel,
    SuggestStatementModel,
    SuggestDescriptionModel,
)
from aegis_ai.features.cve.data_models import CVEFeatureInput
from aegis_ai.prompt import AegisPrompt

logger = logging.getLogger(__name__)


class SuggestImpact(Feature):
    """Based on current CVE information and context assert an aggregated impact."""

    def post_process(self, output, call_str):
        # read the suggested cvss3_score
        try:
            cvss3_score = float(output.cvss3_score)
        except ValueError:
            cvss3_score = float("nan")

        # compute CVSS3 score from the suggested cvss3_vector
        try:
            cvss3_score_by_vector = cvss.CVSS3(output.cvss3_vector).scores()[0]
        except Exception:
            cvss3_score_by_vector = float("nan")

        if cvss3_score == cvss3_score_by_vector:
            # already consistent
            return

        logger.warning(
            f"{call_str}: adjusting cvss3_score to match cvss3_vector: {cvss3_score} -> {cvss3_score_by_vector}"
        )
        output.cvss3_score = f"{cvss3_score_by_vector}"

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and assess basic CVSS 3.1 vector/score from the perspective of Red Hat customers.  Based on the CVSS 3.1 score predict the impact (LOW/MODERATE/IMPORTANT/CRITICAL). Ignore existing labels and decide independently.",
            goals="""
                - User Interaction is Required for an application to connect a malicious server.
                - Denial of Service (DoS) has lower impact on applications compared to daemons and servers.
                - Do not base analysis decisions on which RH products are affected.
                - Based on all the previous analysis, identify the most appropriate CVSS 3.1 vector and score - using this identify impact rating (Critical, Important, Moderate, or Low).
            """,
            rules="""
                - Assess impact within the context of Red Hat's defense-in-depth architecture, specifically noting that mandatory MFA and least privilege access can limit attack surface.  
                - Use the following Red Hat Impact scale as a guide:
                    - CRITICAL: A remote unauthenticated user can execute arbitrary code. Does not require user interaction.  9.0 < cvss3_score
                    - IMPORTANT: Allows local users to gain privileges.  Unauthenticated remote users can view resources.  Authenticated remote users can execute arbitrary code.  7.0 < cvss3_score <= 9.0
                    - MODERATE: Harder to exploit or limited scope/conditions.  4.0 < cvss3_score <= 7.0
                    - LOW: Unlikely or minimal consequence.  cvss3_score <= 4.0
                - Consider: basic CVSS 3.1 metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability.
                - Retrieve and summarise context from vulnerability reference urls.
                - Use github mcp tool to retrieve additional context from vulnerability reference url.
                - Always use kernel_cve tool to provide additional CVE context if CVE component is kernel.
                - If cisa_kev_tool tool is available check if there are any related known exploits.
                - Output
                    - output a plausible CVSS 3.1 base vector and score.
                    - output a impact (which directly correlates to identified CVSS score)
                    - Provide confidence in [0.00..1.00]. Keep explanations concise.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=SuggestImpactModel.model_json_schema(),
        )
        result = await self.run_if_safe(prompt, output_type=SuggestImpactModel)
        call_str = f"{self.__class__.__name__}({cve_id})"
        self.post_process(result.output, call_str)
        return result


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="From the CVE JSON, identify the most specific CWE that matches the root cause of software weakness. Ignore any pre-labeled CWE.",
            goals="""
                - Prefer the most specific CWE over broad parents.
                - Return a short explanation and confidence.
            """,
            rules="""
                - When CVE component is kernel always use kernel_cve tool to retrieve additional context.
                - Retrieve and summarise additional context from vulnerability reference urls.
                    - Use github mcp tool to resolve vulnerability reference urls.
                    - Use tavily to resolve vulnerability reference urls.
                    - Use google search to resolve vulnerability reference urls.
                - Identify set of candidate CWEs - always use the mitre cwe tool retrieve_allowed_cwe_ids to filter candidate CWE list.
                    - Analyze vulnerability, identify CWE that matches root cause of weakness, being careful about memory management and buffer overflows.
                    - Perform search using mitre cwe tool cwe_searches to identify candidate CWEs (perform cwe_searches with 2-3 different queries).
                - Use mitre cwe retrieve_cwes tool to get additional information on candidate CWEs.
                - Select the top 2-3 most applicable CWEs (preference on applicability and higher similarity score) from the final set of candidate CWEs.
                - The final list of suggested CWEs should be ranked from most to least applicable to the vulnerability. For example, the first item in the array should be the most applicable CWE based on entire vulnerability analysis.
                Output should include:
                - cwe: Return ordered list of top 2–3 applicable CWE IDs (ex. ["CWE-94"])
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


class SuggestDescriptionText(Feature):
    """Based on current CVE information and context suggest a description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Suggest the CVE description and title to be brief, clear, and accurate. If missing, propose them.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
            """,
            rules="""
                Description: one short paragraph of the form:
                "A flaw was found in [component]. This vulnerability allows [impact] via [vector]."
                - No versioning or extra commentary.
                Title: <= 20 words, include product/component and vulnerability type.
                Do not duplicate fields like versions; keep it focused and professional.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=SuggestDescriptionModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=SuggestDescriptionModel)


class SuggestStatementText(Feature):
    """Based on current CVE information and context suggest a statement."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        prompt = AegisPrompt(
            user_instruction="Suggest the CVE statement to briefly explain RH-specific context for impact; leave empty if none.",
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
            output_schema=SuggestStatementModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, output_type=SuggestStatementModel)


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
