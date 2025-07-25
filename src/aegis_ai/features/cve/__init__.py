import logging

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

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided CVE JSON object and suggest an overall impact rating for the CVE",
            goals="""
                # Task:
                Given a CVE ID or CVE description containing a description of a vulnerability, draft CVSS, affected components and other information generate an impact rating based on the following four-point scale used by Red Hat:
                * CRITICAL: This rating is given to flaws that could be easily exploited by a remote unauthenticated attacker and lead to system compromise (arbitrary code execution) without requiring user interaction, or easily cause system compromise via inference end points on AI systems. Flaws that require authentication, local or physical access to a system, or an unlikely configuration are not classified as Critical impact. These are the types of vulnerabilities that can be exploited by worms.
                * IMPORTANT: This rating is given to flaws that can easily compromise the confidentiality, integrity or availability of resources. These are the types of vulnerabilities that allow local or authenticated users to gain additional privileges, allow unauthenticated remote users to view resources that should otherwise be protected by authentication or other controls, allow authenticated remote users to execute arbitrary code, allow remote users to cause a denial of service, or can cause system compromise via inference end points on AI systems.
                * MODERATE: This rating is given to flaws that may be more difficult to exploit but could still lead to some compromise of the confidentiality, integrity or availability of resources under certain circumstances. It is also given to flaws that could be exploited to cause denial of service-like conditions on AI systems via an inference end point, or allow attackers to steal other users’ data from the AI system without authorization. These are the types of vulnerabilities that could have had a Critical or Important impact but are less easily exploited based on a technical evaluation of the flaw and/or affect unlikely configurations.
                * LOW: This rating is given to all other issues that may have a security impact. These are the types of vulnerabilities that are believed to require unlikely circumstances to be able to be exploited, or where a successful exploit would give minimal consequences. This includes flaws that are present in a program’s source code but to which no current or theoretically possible, but unproven, exploitation vectors exist or were found during the technical analysis of the flaw.
                
                # Instructions for Analysis:
                
                Thorough Traversal: Recursively traverse the entire JSON object, including nested arrays and objects.
            """,
            rules="""
                1.  Analyze the provided CVE data for information related to:
                    * Attack vector (remote, local, physical)
                    * Authentication requirements
                    * User interaction requirements
                    * Impact on confidentiality
                    * Impact on integrity
                    * Impact on availability
                    * Potential for arbitrary code execution
                    * Potential for privilege escalation
                    * Potential for denial of service
                  and generate a red hat specific CVSS3 and CVSS4 score to help suggest impact.
                2. Analysis should be based on the provided JSON against all known CVEs affecting Red Hat products.
                3. The reasoning should not take into account which Red Hat products are affected by the flaw.
                4. Denial of Service (DoS) flaws are usually not IMPORTANT if their scope is limited to an application.
                5. A User Interaction is usually Required (UI:R in CVSS) in case an application connects a malicious server to trigger the flaw.
                6. Provide a confidence % in how accurate (based on training material, reasoning) this assessment is.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=SuggestImpactModel.model_json_schema(),
        )
        return await self.agent.run(prompt.to_string(), output_type=SuggestImpactModel)


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided CVE JSON object and suggest CWE-ID(s) for the CVE",
            goals="""
                Given a description of a Common Vulnerabilities and Exposures (CVE), accurately predict its Common Weakness Enumeration (CWE). List all CWE that are applicable.
                
                Provide the predicted CWE identifier and a brief explanation for the reasoning behind the prediction.
                
                Provide a confidence % representing how confident you are this is correct CWE.
                
                Assist users in understanding the potential software weakness associated with a given vulnerability.
                
                # Instructions for Analysis:
                
                Thorough Traversal: Recursively traverse the entire provided JSON object, including nested arrays and objects.
            """,
            rules="""
                Input Processing:
                
                a) Receive and process textual descriptions of CVEs.
                
                b) Identify key characteristics and patterns within the CVE description relevant to potential software weaknesses.
                
                # CWE Prediction:
                
                a) Based on the analysis of the CVE description, predict the most likely CWE.
                
                b) Provide the standard CWE identifier (e.g., CWE-119).
                
                c) Offer a concise explanation outlining the connection between the CVE description and the predicted CWE.
                
                d) Avoid predicting CWEs that are discouraged or prohibited for Vulnerability Mapping by MITRE.  In particular, do not suggest CWE-264 and CWE-269.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=SuggestCWEModel.model_json_schema(),
        )
        return await self.agent.run(prompt.to_string(), output_type=SuggestCWEModel)


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided CVE JSON object and identify any instances of Personally Identifiable Information (PII).",
            goals="""
            # Definition of PII for this task:
            
                PII includes, but is not limited to:
                    Direct Identifiers: Full names, email addresses, phone numbers, passwords, social security numbers (SSN), national identification numbers, passport numbers, driver's license numbers, bank account numbers, credit card numbers.
                    Indirect Identifiers (that can be linked to an individual): Dates of birth, home addresses, precise geographical coordinates, IP addresses, MAC addresses, device IDs, biometric data (e.g., fingerprints, facial recognition data), unique identifiers from cookies or advertising.
                    Sensitive Information: Health information, genetic information, racial or ethnic origin, political opinions, religious or philosophical beliefs, trade union membership, sexual orientation, criminal records.
            
            # Instructions for Analysis:
            
                Thorough Traversal: Recursively traverse the entire JSON object, including nested arrays and objects.
                Key and Value Analysis: Examine both the keys (field names) and values within the JSON. PII can sometimes be indicated by a key name (e.g., "email", "phone_number") even if the value is empty or generic, but focus primarily on values.
                Pattern Recognition: Look for common patterns associated with PII, such as:
                    Email address formats (e.g., user@domain.com)
                    Phone number formats (various international formats)
                    Numerical sequences that resemble Social Security numbers/national IDs/credit card numbers (consider common lengths and checksums if possible, but err on the side of caution).
                    Keywords in keys or values that suggest PII (e.g., "name", "address", "dob", "ssn", "health", "policy").
                    Anything that looks like a secure password or secret
                Contextual Understanding: Consider the context of the data. For example, a street name alone isn't PII, but a combination of street, city, and postal code often is.
            
                The following example json
            
                ```json
                {"title":"this contains jim@webomposite.com"}
                ```
                So the analysis would identify `jim@webcomposite.com` as PII because it contains an email address.
            
                Taking another example
                ```json
                {"title":"this contains 035-48-2559"},"description":"The fone is +420733228297"}
                ```
                The analysis should identify `035-48-3559` as a ssn and identify +420733228297 as a phone number.
            
                Example 1: Name and Home Address
                ```json
                {
                  "user_profile": {
                    "name": "Alice Wonderland",
                    "contact": {
                      "street": "123 Rabbit Hole Lane",
                      "city": "Wonderland",
                      "zip": "10001"
                    },
                    "preferences": ["tea party", "chess"]
                  },
                  "activity_log": {
                    "event": "logged_in",
                    "timestamp": "2024-05-29T10:30:00Z"
                  }
                }
                ```
            
                Analysis Should Identify addresses:
            
                    Alice Wonderland as a Full Name.
                    123 Rabbit Hole Lane as part of a Home Address.
                    Wonderland as part of a Home Address.
                    10001 as part of a Home Address.
            
                Example 2: Date of Birth and IP Address
                ```json
                {
                  "system_event": {
                    "event_id": "SYS-87654",
                    "client_ip": "192.168.1.100",
                    "details": {
                      "user_agent": "Mozilla/5.0...",
                      "session_start": "2025-05-29T14:15:00Z"
                    }
                  },
                  "customer_data": {
                    "customer_id": "CUST-9988",
                    "dob": "1990-07-15"
                  }
                }
                ```
                Analysis Should Identify:
            
                    192.168.1.100 as an IP Address.
                    1990-07-15 as a Date of Birth.
            
                Example 3: Credit Card Number and Health Information
                ```json
                {
                  "payment_info": {
                    "order_id": "ORD-54321",
                    "card_number": "4111222233334444",
                    "expiry_date": "12/28"
                  },
                  "medical_record": {
                    "record_id": "MR-ALPHA-001",
                    "diagnosis": "Seasonal allergies",
                    "patient_notes": "Patient reported sneezing and watery eyes.",
                    "genetic_marker": "HLA-DRB1"
                  }
                }
                ```
                Analysis Should Identify:
            
                    4111222233334444 as a Credit Card Number.
                    Seasonal allergies as Health Information.
                    Patient reported sneezing and watery eyes. as Health Information.
                    HLA-DRB1 as Genetic Information.
            
                Example 4: National Identification Number and Biometric Data Hint
                ```json
                {
                  "enrollment_form": {
                    "form_id": "ENR-007",
                    "applicant_id": "ID-9876543210",
                    "biometric_hash": "fingerprint_hash_abc123xyz",
                    "nationality": "Czech"
                  }
                }
            
                Analysis Should Identify:
            
                    ID-9876543210 as a National Identification Number (assuming context where ID- prefix implies a national ID).
                    fingerprint_hash_abc123xyz as Biometric Data.
            """,
            rules="""
            # Rules for output fields
                explanation:
                    If PII is found, create a bulleted list where each item is formatted as PII type:"exact string".
                    The exact string cannot be empty.
                    The PII type should be a concise description (e.g., "Gender","Race","Email Address", "Phone Number", "Physical Address", "Health Information").
                    The "exact string" must be the literal value from the JSON that constitutes the PII.
                    A separate bullet point is used for each instance of PII found.
                    If NO PII is found, this field should be an empty string ("").
                confidence: Generate a score between 0.00 and 1.00 (two decimal places) indicating confidence in the PII analysis. A higher score means greater certainty.
                contains_PII: Set to true if any PII was identified, false otherwise.
            
            # Additional guidelines for report
            - Only report on PII that is present in the provided json.
            - Explanation should only contain list of PII found.
            - Do not include any code in this report.
            - Do not gratitiously repeat information.
            - Do not insert line breaks (ex. \n).
            - Do not invent or add any information that is not present in the given context.
            
            If PII is found, include a bulleted list of each occurrence of PII in explanation.
            Each bullet point should contain the PII type and the exact string found, formatted as "PII type:'exact string'".
            If no PII is found, leave this section empty.
            
            To determine how to set contains_PII:
            1. If you find at least one instance of PII, set contains_pii:True.
            2. If you do not find any PII, set contains_pii:False.

            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=PIIReportModel.model_json_schema(),
        )
        return await self.agent.run(prompt.to_string(), output_type=PIIReportModel)


class RewriteDescriptionText(Feature):
    """Based on current CVE information and context rewrite/create description and title."""

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided JSON object and rewrite cve description for it. The goal of the description is to briefly provide an overview of the CVE. If the cve description exists, rewrite it - if it does not exist suggest new text.",
            goals="""
                * Evaluate the quality of CVE description text from the perspective of a security analyst.
                * Provide an overall text quality score for a given CVE description based on a comparison with previous Red Hat CVEs.
                * Offer a confidence score for the analysis performed.
                * Generate an improved, rewritten version of the CVE description for clarity.
            """,
            rules="""
                1) Input Analysis:
                
                a) When provided with a CVE identifier or a CVE description, analyze the text for clarity, conciseness, and completeness from a security analyst's viewpoint.
                
                b) Identify any jargon, ambiguity, or missing information that could hinder understanding.
                
                c) Ensure writing is from the point of view of Red Hat security analysis
                
                2) Scoring:
                
                a) Calculate a text quality score reflecting how well the CVE description explains the security vulnerability, drawing comparisons with historical Red Hat CVE descriptions as a benchmark.
                
                b) Assign a confidence score to the analysis, indicating the certainty of the evaluation and the quality score.
                
                3) Rewriting:
                
                a) Generate an alternative CVE description that is clearer, more concise, and easier for a security analyst to understand.
                
                b) Ensure the rewritten description accurately conveys the essential information about the vulnerability.
                
                c) Maintain a professional and informative tone in the rewritten description.
                
                d) Generate only the vulnerability description in the following format:\n"
                
                   "A flaw was found in [product/component]. This vulnerability allows [impact description] via [attack vector].\n"
                
                   Do not include any versioning information, introductory text, or explanations. Return only the description.
                
                e) Generate a short and precise title for this vulnerability.
                   Avoid including versioning, introductory text, or explanations.
                   The title should be concise, professional, and no longer than 7 words.
                   The title should contain the product name and the type of vulnerability.
                
                # Further Guidelines for writing CVE description
                
                The CVE Description field should provide information to help customers quickly and easily understand the flaw's threat
                to their system.
                
                CVE Description is a basic description of the following information:
                
                    * The type of vulnerability and where it exists
                    * Who or what can exploit the flaw
                    * How the flaw can be exploited
                
                The following is a guideline for the Description structure:
                
                The type of flaw (based on CWE) and what it can do
                For example, "A buffer overflow", "An integer overflow", "A NULL pointer dereference", or "A privilege escalation flaw". Suggested phrasing examples:
                    "A flawed bounds check in the xxxx function leads to... "
                    "A Cross-Site Request Forgery (CSRF) issue can lead to..."
                    "A cross-site scripting (XSS) flaw leading to..."
                Who can exploit the flaw
                For example, local or remote attacker, authenticated or unauthenticated user or attacker, privileged or unprivileged guest user, man-in-the-middle attacker, or a malicious server. Suggested phrasing examples:
                    "An attacker with CREATE and DROP table privileges and shell access to the database server could use this issue to ..."
                    "A local attacker could use this issue to cause a denial of service by mounting a specially crafted [file system type, such as ext4] file system."
                    "This flaw allows an attacker to..."
                How the flaw can be exploited
                For example, "specially crafted packet or request" or "specially crafted text file". Suggested phrasing examples:
                    "An attacker could create a specially crafted image file that, when opened by a victim, could cause an application to crash or allow arbitrary code execution."
                    "If a carefully crafted file-type file was loaded by an application linked against [affected-library-name], the application could crash or allow arbitrary code execution with the privileges of the user running the application."
                Exploitation consequences
                For example, a denial of service, code execution, privilege escalation, or information disclosure. Suggested phrasing examples:
                    "A user in a guest could leverage this flaw to cause a denial of service (guest hang or crash) or possibly escalate their privileges within the host."
                    "This could lead to a denial of service if a user browsed a specially crafted [file system type, such as ext4] file system, for example, by running 'ls'."
                
                ## Things to do:
                
                The description should be unique and distinguishable between similar-looking vulnerabilities. For example, if there are two CVEs reported for a component and both of them are CSRF attacks, ensure customers can differentiate one from another based on attack vector, attack surface, or data breach.
                Follow the correct naming conventions and capitalization wherever possible, such as product names. For example, using names such as Gluster or Samba, and using protocols such as HTTPS, FTP, or TLS.
                Use the Statement to anticipate customer questions. In particular, if our flaw impact (Severity rating) is significantly different from the NVD severity rating defined by their CVSS Base Score, this should be explained. For instance, if the NVD CVSS Base Score is in the range they define as High or Critical, but our rating is Moderate or Low, customers will seek an explanation for why our rating is lower. This explanation is also important for customers responding to reports from vulnerability scanners.
                Severity ratings and CVSS Base Score Ranges:
                    none    0.0
                    low       0.1 - 3.9
                    medium  4.0 - 6.9
                    high     7.0 - 8.9
                    critical 9.0 - 10.0
                
                ## Things not to do:
                
                The use of acronyms should be avoided when possible because customers might not know the acronym. When it’s necessary to use an acronym, add the corresponding full form. For example, use "Active Directory Domain Controller (AD DC)" rather than just writing “AD DC”.
                Engineers should refrain from using generic Confidentiality, Integrity, and Availability (CIA) statement boilerplate templates. For example, "The highest threat from this vulnerability is to data confidentiality". Instead, describe what kind of restricted information can be obtained and the amount of information disclosure.
                Information that is already included in other fields. For example, the CVE number or affected versions, which belong in Comment #0 of the flaw bug.
                
                If multiple Red Hat products are affected, do not include the name of a specific product in the description. The per-product technical description, affected state, or any other special cases belongs in the Statement.
                
                # Further Guidelines for CVE Title
                
                The title should describe *only* the core technical issue based *only* on the provided input.
                
                ### Instructions:
                
                1.  Start the paragraph *exactly* like this: "A flaw was found in 'component_name'."
                2.  Continue by *briefly* summarizing from the "Original Description Snippet" and other hints:
                    * The **technical flaw** and its direct effect (e.g., 'buffer overflow leads to...').
                    * The **attacker profile** (e.g., 'local attacker can...').
                    * The **exploitation vector** (e.g., '...via a crafted file.').
                    * The **primary consequence** (e.g., 'This can cause a denial of service.').
                3.  Combine these points into a single, flowing paragraph.
                4.  **Crucially, DO NOT include:**
                    * Information about disclosure status.
                    * Any classification (like 'problematic', 'important').
                    * How the bug was found (like 'fuzzer-identified').
                    * Plans for fixing it or mitigation efforts (these are handled separately).
                    * CVSS scores or specific vector strings (these are displayed separately).
                    * Any generic text, explanations, or meta-commentary not directly describing the flaw's technical nature.
                5.  **DO NOT** use headings, bold text (other than the starting phrase if needed by a template), bullet points, or line breaks. It must be one single paragraph.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=RewriteDescriptionModel.model_json_schema(),
        )
        return await self.agent.run(
            prompt.to_string(), output_type=RewriteDescriptionModel
        )


class RewriteStatementText(Feature):
    """Based on current CVE information and context rewrite/create statement."""

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided JSON object and rewrite CVE statement for it. The goal of the statement is explain the context for the CVE impact with respect to Red Hat supported products. If the CVE statement exists, rewrite it - if it does not exist suggest new text.",
            goals="""
                * Evaluate the quality of existing CVE statement text from the perspective of a security analyst.
                * Provide an overall text quality score for a given CVE description based on a comparison with previous Red Hat CVEs.
                * Offer a confidence score for the analysis performed.
                * Generate an improved, rewritten version of the CVE statement for clarity.
                * The rewritten statement does not duplicate information provided in the description field.
                * The rewritten statement does not include any low-level technical details, such as specific code changes.
                * The rewritten statement does not suggest customers to apply upstream patches or to rebuild software from source code.
                * If no additional context is available, the rewritten statement is empty.
            """,
            rules="""
                1) Input Analysis:
                
                When provided with a CVE identifier or a CVE description, analyze the CVE statement text for clarity, conciseness, and correctness from a security analyst's viewpoint.
                
                The CVE statement will explain why an impact is either higher or lower than expected, especially if Red Hat products are not impacted.
                
                2) Scoring:
                
                a) Calculate a text quality score reflecting how well the CVE statement explains the security vulnerability, drawing comparisons with historical Red Hat CVE statements as a benchmark.
                
                b) Assign a confidence score to the analysis, indicating the certainty of the evaluation and the quality score.
                
                3) Rewriting:
                
                a) Generate an alternative CVE statement that is clearer, more concise, and easier for customers to understand.
                
                b) Ensure the rewritten statement accurately conveys the context and rationale for the impact score modulo relation to Red Hat
                 supported products.
                
                c) Do not duplicate information available in other fields, such as flaw description.  Do not describe low-level technical details.
                
                
                # Further Guidelines to Writing a Comprehensive Vulnerability Statement
                
                A CVE's statement covers more than just the rationale behind an impact rating. Additionally it touches on:
                
                  - A direct opportunity to provide value beyond what’s easily found in an internet search.
                  - Additional technical details which clarify the scope of impact. Make it easy for the subset of unaffected customers (because of how they configure their deployment) to discover this.
                  - Explaining the affected function at code level is too much detail, it is better to explain:
                      - how a vulnerable function/service impacts the system
                      - what successful exploitation looks like
                      - or how difficult it is to exploit
                
                A flaw's Statement provides additional information about Red Hat’s response to a security issue and displays prominently on the flaw's CVE page where customers are likely to see it.
                
                Statements are especially important for flaws with a higher impact, which are likely to receive more customer attention because they hit the media, are in a critical component, or are more highly rated by other sources. Statements are even more important when our triage decisions may seem surprising from a naïve reading of description & CVSS.
                
                If a Statement prevents a support call, it has succeeded. If secalert is asked to help a customer understand a flaw, the answer can often be summarized in a Statement, and the customer or support person is asked to confirm whether the Statement answers their question. This interaction can then inform future Statements.
                
                ## Elements of an excellent statement
                
                To write an effective and excellent statement, several elements are necessary. The elements provide specific information that customers will find useful.
                
                  - Explains the RH impact rating and any difference between industry ratings utilizing CIA logic.
                  - Explains any differences in CVSS vectors in a Red Hat calculated score.
                  - References affected Red Hat components (vs upstream).
                  - Includes conditions and technical detail specific to Red Hat configuration, patching, and build details.
                  - Includes any statements of fact as necessary.
                
                ## Language and way of speaking
                
                Do not worry about the complexity of language. The statement should not contain complicated, legal sounding content. Keep the statements conversational, as if one engineer is talking to another. This will make the information easier to follow and understand.
                
                  - Avoid overly complicated language.
                  - Write simply and clearly, using words that everyone can understand.
                  - Sound confident.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=RewriteStatementModel.model_json_schema(),
        )
        return await self.agent.run(
            prompt.to_string(), output_type=RewriteStatementModel
        )


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID):
        prompt = AegisPrompt(
            user_instruction="Explain the differences of cvss score attributed to CVE between supplied redhat CVE context and nvd CVE.",
            goals="""
                * Given a Common Vulnerabilities and Exposures (CVE) identifier, retrieve  its Red Hat CVSS and NVD(NIST) CVSS score
                * compare the Red Hat Common Vulnerability Scoring System (CVSS) score with the CVSS score reported by the National Vulnerability Database (NVD).
                * Identify and clearly explain any differences between the Red Hat and NVD CVSS scores.
                * Provide context for the CVSS metrics and how they contribute to the overall score, focusing on explaining why the scores might differ.
            """,
            # FIXME: Do we ever track temporal and environmental scores in OSIM?
            # I have never seen these metrics included in the cvss3/cvss4 fields.
            rules="""
                1) Input Analysis:
                
                    a) Accept a Red Hat CVE identifier as the primary input.
                
                    b) Validate the format of the CVE identifier.
                
                2) Data Retrieval:
                
                    a) Access or simulate access to information regarding the CVSS scores for the given CVE from both Red Hat and NVD sources.
                
                    b) Clearly state the retrieved CVSS base scores, temporal scores (if available), and environmental scores (if available) from both sources.
                
                    c) Include the CVSS vector strings for both Red Hat and NVD.
                
                3) Comparison and Explanation:
                
                    a) Directly compare the base, temporal, and environmental scores (if present) from both sources.
                
                    b) Identify specific differences in the individual CVSS metrics (e.g., Attack Vector, Attack Complexity, Confidentiality Impact) that contribute to any overall score discrepancies.
                
                    c) Explain the potential reasons for these differences, such as variations in vulnerability assessment, data interpretation, or the timing of the analysis by each organization.
                
                    d) Use clear and concise language, avoiding technical jargon where possible, or explaining it when necessary.
                
                    e) If there is no difference in the CVSS scores, or the information is not available, return an empty explanation.
                
                
                Format
                If there is no difference in the CVSS scores, provide an empty explanation.  Otherwise:
                * first line should contain Red Hat CVSS
                * second line should contain NVD CVSS
                * third line should contain confidence % in explaining the difference
                * Next provide rationale and explain difference between Red Hat and NVD CVSS score
                
                
                # JSON for analysis
                The cvss diff analysis performed on supplied CVE context which means you also must retrieve NVD (NIST) cvss for this CVE
                and compare and explain why there is a difference.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            output_schema=CVSSDiffExplainerModel.model_json_schema(),
        )
        return await self.agent.run(
            prompt.to_string(), output_type=CVSSDiffExplainerModel
        )
