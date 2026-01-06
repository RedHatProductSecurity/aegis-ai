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
            user_instruction="Analyze the CVE JSON and derive a CVSS v3.1 base vector and score with metric-by-metric rationale from the perspective of Red Hat customers. Based on the score, select the impact (LOW/MODERATE/IMPORTANT/CRITICAL). Ignore any pre-labeled impact/CVSS and decide independently.",
            goals="""
                - Return exactly one CVSS:3.1 base vector and score consistent with each other.
                - Provide short reasoning for each base metric (AV, AC, PR, UI, S, C, I, A).
                - Prefer AV:L for local-only flaws; use AV:N only if remote/network reachable without local access; AV:A when limited to same-link/adjacent network; AV:P for physical.
                - For DoS-only flaws, emphasize A over C/I; for LPE, emphasize PR>UI and I (and C when secrets are exposed).
                - Do not base metric choices on which RH products are affected; reason from technical preconditions and exploit mechanics.
                - Pick impact (Critical/Important/Moderate/Low) from the computed score.
            """,
            rules="""
                - Output format (must follow exactly):
                    - cvss3_vector: "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
                      where AV in [N,A,L,P], AC in [L,H], PR in [N,L,H], UI in [N,R], S in [U,C], C/I/A in [N,L,H].
                    - cvss3_score: numeric string matching the vector (we will verify and adjust if needed).
                    - impact: Critical/Important/Moderate/Low based on the score.
                - Metric selection guide:
                    - AV: N if reachable over network from off-host; A if same subnet/Bluetooth/802.11 link-limited; L if requires local account/session/CLI/local IPC; P if requires physical access.
                    - AC: H if requires uncommon configuration, precise timing/race, multiple conditions, or lengthy preparation; else L.
                    - PR: N if no prior auth; L if basic/local user privileges are enough; H if admin/root/high-privileges are required to trigger.
                    - UI: R if victim must click/open/provide content; else N.
                    - S: C if exploitation crosses a trust boundary (e.g., container escape, VM escape, kernel boundary affecting other contexts); else U.
                    - CIA: Set each based on consequences described: use A for availability-only DoS; use C/I when data disclosure/modification or code execution with escalated privileges is plausible.
                - Consider Red Hat hardening defaults (SELinux enforcing, least privilege) only to inform AC and S, not AV.
                - Retrieve and summarize additional context from vulnerability references:
                    - Use github mcp and web search tools to resolve reference URLs.
                    - Always use kernel_cve tool if the component is the Linux kernel.
                    - If cisa_kev_tool is available, check for known exploits.
                - Confidence:
                    - Calibrate confidence to the fraction of base metrics you are ≥80% sure about (e.g., 0.75 if 6/8 are certain).
                - Output
                    - Provide the vector and score first, then impact, then a concise explanation with metric-by-metric rationale.
                    - Keep explanations concise.
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
                - Retrieve and summarise additional context strictly from vulnerability reference URLs and CWE tool outputs.
                    - Prefer mitre_cwe tools (retrieve_allowed_cwe_ids, search_cwes, retrieve_cwes) for CWE selection and definitions.
                    - Use github mcp tool to resolve vulnerability reference URLs if present.
                    - Avoid using general-purpose web search or encyclopedic tools for CWE selection unless references are insufficient.
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
            user_instruction="Analyze the CVE JSON and suggest the CVE description and title to be brief, clear, and accurate. If missing, propose them. Write for a non-technical/executive audience (e.g., a CISO) using plain English; avoid jargon and define unavoidable terms briefly.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
                - The description should be 2–5 sentences and easy to read.
                - The title should briefly summarize the core impact and trigger in one line.
            """,
            rules="""
                'description': one short paragraph.
                - Begin with: "A flaw was found in <component>."
                - Clearly state: who can exploit the flaw (e.g., a remote attacker, a local user, a malicious server), how it can be exploited (method/conditions), and the concrete consequences.
                - Include the vulnerability type when clear (use CWE category when obvious), the affected component, the trigger/cause, and the primary impact.
                - Highlight the most important consequence first. Prefer domain phrases such as "arbitrary code execution", "privilege escalation", "information disclosure", or "Denial of Service (DoS)".
                - Use plain English; avoid deep implementation jargon. If a function or symbol name is central to exploitation, you may mention a single example and explain it briefly.
                - If a term or acronym is needed, briefly define it and expand the acronym in parentheses on first use.
                - Do not include product/version lists, package names, or mitigation/update guidance.
                - Avoid generic CIA boilerplate; name the concrete impact (e.g., data disclosure, code execution, denial of service).
                - Ambiguity and uncertainty:
                  - Do NOT invent a specific component, function, trigger, CWE, or impact if the source data and references do not clearly support it.
                  - If a single component or trigger cannot be reliably identified, use neutral wording (e.g., "in the affected component") and describe the mechanism at a high level.
                  - Prefer calibrated phrasing when evidence is weak (e.g., "may allow", "can enable") rather than asserting specifics.
                  - Only include a CWE category or precise impact (e.g., "arbitrary code execution", "privilege escalation") when it is well-supported; otherwise, use a generic but accurate type (e.g., "input validation vulnerability", "memory corruption vulnerability") or simply "vulnerability".
                'title': <= 20 words, summarize the description; include product/component and vulnerability type or consequence.
                - Style: "<Component>: <primary consequence> via <trigger/cause>" when applicable.
                - The title may include a specific function or primitive if it is the salient trigger; avoid extraneous implementation details.
                - If the trigger is unclear, omit the "via <trigger/cause>" clause. If the component is unclear, name the project/product or keep a consequence-first title without fabricating specifics.
                - Strictly exclude versions: never include any version numbers or ranges (e.g., "5.0.0", "v2", "2.x", "9.x and earlier") in the title.
                - Keep it focused and professional.
                - 'description' and 'title' need to be consistent with each other.
                - Never output meta-diagnostic text such as "information is inconsistent", "insufficient data", "cannot determine", or similar. Provide the best-supported description instead with calibrated confidence.
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
            user_instruction=f"Analyze the provided CVE context ({cve_id}) and generate a Red Hat specific Statement and Mitigation.",
            goals="""
            - Provide two fields tailored for Red Hat products:
              1) Suggested Statement: brief rationale of impact in RH context
              2) Suggested Mitigation: practical configuration or operational workaround tailored to Red Hat
            - Keep outputs concise and consistent; avoid contradiction between fields.
            """,
            rules=f"""
            ### STATEMENT (suggested_statement)
            - Focus on impact and RH relevance (deployment model, defaults, hardening).
            - Start with a concise severity-and-why sentence tailored for Red Hat, e.g.:
              "This vulnerability is rated Moderate for Red Hat because ..." or
              "In the Red Hat context, impact is limited because ...".
            - Explain briefly why impact applies (e.g., feature disabled by default, needs uncommon configuration, requires physical access, short-lived CLI use).
            - Explicitly note scope and applicability:
              - Call out affected/unaffected Red Hat product versions when the rationale depends on defaults (e.g., feature disabled by default on RHEL 8/9).
              - If the vulnerability requires a feature that is disabled by default on common RH releases, state those releases are not affected and why.
              - If exploit requires physical access or specialized hardware, highlight that requirement; mention if virtualized/emulated devices could still enable exploitation.
            - When applicable, note preconditions and what is not affected (e.g., versions, roles, disabled-by-default features).
            - Must NOT:
              - Duplicate the CVE description verbatim.
              - Include code-level details or command examples.
              - Mention mitigation steps or software updates/patching.
            - Style: 2–4 concise sentences, < 1000 characters total.
            
            ### MITIGATION (suggested_mitigation)
            - **Definition:** A configuration or operational control that reduces exposure without patching (e.g., config file, environment variable or feature toggle, sysctl, service disable, or removing optional packages). Prefer a conservative, documented mitigation over declaring that none exists.
            - **Prohibitions:**
                - **NEVER** suggest updating/patching software.
                - **NEVER** invent config flags or commands.
                - **NEVER** use the term 'update'.
                - **NEVER** suggest dangerous commands (`rm -rf`, `chmod 777`, disabling SELinux globally) without explicit, dire warnings.
            - **Decision process (use before considering fallback):**
                1. Identify what exposes the vulnerable component in RH context (network daemon, optional plugin/format, kernel module/driver, desktop-only feature).
                2. Check for documented, supported controls to reduce exposure: restrict network reachability, disable optional features/plugins/filters, sandbox, or blacklist/avoid autoloading kernel modules.
                3. If any safe, documented configuration or operational control exists, provide it even if it only partially reduces risk; clearly note caveats.
                4. Only if no such control exists or the CVE does not affect RH products, proceed to the fallback.
            - **Structure:**
                1. Summary of action ("Disable the X service").
                2. Command examples (`sysctl`, `systemctl`).
                3. Caveats ("This may impact performance").
                4. Always warn if there is a potential for reload and restarts (If CVE is related to a service and mitigation provides concrete command line instructions, always provide a warning)
            - Prefer configuration-only or operational hardening patterns when applicable:
                - Limit service exposure: restrict access to trusted networks, apply rate limiting or firewall rules, and enable protocol validation features if available (e.g., DNSSEC for resolvers).
                - Disable optional features required to trigger the flaw: use configuration or environment toggles to turn off risky engines or modes; remove optional packages that provide the risky component if not needed.
                - Web content engines or embedded browsers (e.g., WebKitGTK): advise avoiding untrusted web content; if exploitation depends on JIT, disable it via a documented toggle when available (example for WebKitGTK: set environment variable JavaScriptCoreUseJIT=0 on affected systems).
                - If exposure is introduced by optional desktop/GUI packages, list common packages that pull in the vulnerable component and suggest removing them if not needed; clearly warn that removing these may also remove GNOME or related packages and break functionality; note that servers remain usable via terminal.
                - For components that process untrusted content (browsers, renderers, document viewers), advise operational controls such as avoiding untrusted content and sandboxing. If a JIT or optional execution engine can be disabled via a documented environment variable or config flag, suggest disabling it (e.g., an environment variable toggle).
                - Kernel driver vulnerabilities: prevent autoloading of the affected module via an /etc/modprobe.d rule (install/blacklist); note that a restart or service reload may be required and may impact functionality.
                - Network daemons (e.g., CUPS, dnsmasq, httpd): restrict service to localhost or trusted networks, disable remote administration, and firewall the relevant port(s) if feasible in your environment.
            - **Fallback:** Use only after the decision process above confirms that no safe, documented configuration or operational control exists in Red Hat products, or if the CVE does not affect Red Hat products (e.g., Windows-only). If any partial risk reduction is possible (e.g., firewalling, limiting to localhost, disabling optional plugins/filters, sandboxing, or blacklisting a kernel module), DO NOT use the fallback. When applicable, YOU MUST USE EXACTLY THIS TEXT:
              "{NO_MITIGATION_TEXT}"
            - Length: < 2000 characters.
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
