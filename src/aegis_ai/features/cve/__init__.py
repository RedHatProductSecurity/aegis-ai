import cvss
import logging
from typing import Any

from aegis_ai import remove_keys
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
from aegis_ai.features.data_models import feature_deps
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
        deps = feature_deps(exclude_osidb_fields=["impact", "rh_cvss_score"])
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
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestImpactModel.model_json_schema(),
        )
        result = await self.run_if_safe(
            prompt, deps=deps, output_type=SuggestImpactModel
        )
        call_str = f"{self.__class__.__name__}({cve_id})"
        self.post_process(
            result.output, call_str
        )  # TODO: extract this to process on SuggestImpactModel data model rather then here.
        return result


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["cwe_id"])
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
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestCWEModel.model_json_schema(),
        )
        return await self.run_if_safe(prompt, deps=deps, output_type=SuggestCWEModel)


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=[])
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
        return await self.run_if_safe(prompt, deps=deps, output_type=PIIReportModel)


class SuggestDescriptionText(Feature):
    """Based on current CVE information and context suggest a description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["title", "cve_description"])
        prompt = AegisPrompt(
            user_instruction="Suggest the CVE description and title to be brief, clear, and accurate. If missing, propose them.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
            """,
            rules="""
                'description': one short paragraph of the form:
                "A flaw was found in [component]. This vulnerability allows [impact] via [vector]."
                - No versioning or extra commentary.
                - Include detailed technical information.
                - Expand each acronym in parentheses behind the acronym in the description text.
                'title': <= 20 words, include product/component and vulnerability type.
                - Do not duplicate fields like versions; keep it focused and professional.
                - 'description' and 'title' need to be consistent with each other.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestDescriptionModel.model_json_schema(),
        )
        return await self.run_if_safe(
            prompt, deps=deps, output_type=SuggestDescriptionModel
        )


class SuggestStatementText(Feature):
    """Based on current CVE information and context suggest a statement and mitigation."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["statement", "mitigation"])
        NO_MITIGATION_TEXT = (
            "Mitigation for this issue is either not available or the currently available "
            "options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, "
            "applicability to widespread installation base, or stability."
        )

        prompt = AegisPrompt(
            user_instruction=(
                f"Analyze the provided CVE context ({cve_id}) and generate a Red Hat specific "
                "Statement and Mitigation plan."
            ),
            goals="""
            You are a Red Hat Product Security analyst. Your goal is to populate two specific fields:

            1. **Suggested Statement**: A technical rationale explaining the impact of this CVE specifically on Red Hat products. This clarifies why Red Hat's severity assessment might differ from the upstream NVD/CVSS score.
            2. **Suggested Mitigation**: A practical, temporary workaround to reduce the attack surface without applying a software update.
            """,
            rules=f"""
            ### GLOBAL STYLE GUIDELINES
            - **Consistency:** Ensure the Statement and Mitigation do not contradict each other.
            - **Explanation:** Provide a brief explanation in the final output justifying your choices for both fields.

            ### FIELD 1: SUGGESTED STATEMENT RULES
            - **Length:** < 1000 characters.
            - **Content:**
                - Focus on *impact*: "The highest threat is to system availability."
                - Explain *why*: "This issue only affects systems with X enabled."
                - If no Red Hat specific context exists (generic flaw), return an empty string.
            - **Prohibitions:**
                - Do NOT duplicate CVE description 
                - Do NOT repeat the technical explanation of the vulnerability already present in the 'description' field.
                - Do NOT mention mitigations here.
                - Do NOT include code blocks.
                - Do NOT include anything about software updates or patching.

            #### SPECIAL LOGIC (HIGHEST PRIORITY)
            Apply these rationales EXACTLY if the conditions are met:

            1. **CASE: Vim Fuzzing Issues**
               - **IF** component is 'vim' **AND** requires explicit script mode ('-S') to trigger:
               - **THEN** State: "Red Hat rates this Low because running an untrusted script with '-S' is equivalent to executing arbitrary code, regardless of the vulnerability."
               - **ELSE** Do not apply this rationale.

            2. **CASE: RHEL 8 Python36 Symlinks**
               - **IF** platform is RHEL 8 **AND** package is 'python36' (symlink only) **AND** interpreter is main 'python3':
               - **THEN** State: "This package is 'Not affected' as it only provides symlinks to the main python3 component."

            3. **CASE: RHEL CLI Tools (Go-based)**
               - **IF** component is a build-time Go dependency **AND** binary is a short-lived CLI tool (not a daemon/service):
               - **THEN** State: "Rated Moderate because the utility is not a long-running service and the dependency is only used at build time."

            4. **CASE: Xorg Server on RHEL 8/9**
               - **IF** component is 'xorg-x11-server' **AND** OS is RHEL 8 or 9:
               - **THEN** State: "Rated Moderate because Xorg server does not run with root privileges in RHEL 8/9."

            ### FIELD 2: SUGGESTED MITIGATION RULES
            - **Length:** < 2000 characters.
            - **Definition:** A configuration change (config file, sysctl, service disable).
            - **Prohibitions:**
                - **NEVER** suggest updating/patching software. 
                - **NEVER** invent config flags or commands.
                - **NEVER** use the term 'update'.
                - **NEVER** suggest dangerous commands (`rm -rf`, `chmod 777`, disabling SELinux globally) without explicit, dire warnings.
            - **Structure:**
                1. Summary of action ("Disable the X service").
                2. Command examples (`sysctl`, `systemctl`).
                3. Caveats ("This may impact performance").
                4. Always warn if there is a potential for reload and restarts (If CVE is related to a service and mitigation provides concrete command line instructions, always provide a warning) 
            - **Fallback:** If no configuration workaround exists (or the only fix is code patching), or if the CVE does not affect Red Hat products (Windows only), YOU MUST USE EXACTLY THIS TEXT:
              "{NO_MITIGATION_TEXT}"
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestStatementModel.model_json_schema(),
        )
        return await self.run_if_safe(
            prompt, deps=deps, output_type=SuggestStatementModel
        )


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=[])
        prompt = AegisPrompt(
            user_instruction="Compare Red Hat CVSS3 vs NVD CVSS3 for the CVE and explain any differences.",
            goals="""
                - Report both base vectors/scores.
                - If identical, explanation must be empty.
            """,
            rules="""
                - Be specific about which metrics drive the difference (AV, AC, PR, UI, CIA).
                - Expand especially on *why* the metrics are different in the Red Hat context.
                - Keep the rationale brief and factual. If no difference, return an empty explanation.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=CVSSDiffExplainerModel.model_json_schema(),
        )
        return await self.run_if_safe(
            prompt, deps=deps, output_type=CVSSDiffExplainerModel
        )
