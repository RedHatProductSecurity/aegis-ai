import pytest
import re
from typing import get_args

from pydantic_evals import Case
from pydantic_evals.evaluators import EvaluationReason, Evaluator

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import SuggestDescriptionText, SuggestDescriptionModel

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    make_eval_reason,
    run_evaluation,
)


# some evaluators are only applicable if the expected output for a specific field is provided
field_evaluators = {
    "suggested_title": create_llm_judge(
        score_name="TitleEvaluator",
        rubric="Score how much the actual suggested_title field is semantically equivalent to the expected suggest_title field.  If the key message is the same but the style is different, the score should not be zero.  If the style is different, the score should not be 1.0.",
        include_expected_output=True,
    ),
    "suggested_description": create_llm_judge(
        score_name="DescriptionEvaluator",
        rubric="Score how much the actual suggested_description field is semantically equivalent to the expected suggest_description field.  If the key message is the same but the style is different, the score should not be zero.  If the style is different, the score should not be 1.0.",
        include_expected_output=True,
    ),
}


class SuggestDescriptionCase(Case):
    def __init__(self, cve_id, expected_title=None, expected_description=None):
        """cve_id given as CVE-YYYY-NUM is the flaw we suggest description for."""
        disclaimer_model = SuggestDescriptionModel.model_fields["disclaimer"]
        disclaimer = get_args(disclaimer_model.annotation)[0]
        expected_output = SuggestDescriptionModel(
            cve_id=cve_id,
            components=[],
            explanation="",
            suggested_title=(expected_title or ""),
            suggested_description=(expected_description or ""),
            confidence=1.0,
            tools_used=[],
            disclaimer=disclaimer,
        )

        # enable field-specific evaluators for this case
        evaluators = tuple(
            field_evaluators[f] for f in field_evaluators if getattr(expected_output, f)
        )

        super().__init__(
            name=f"suggest-description-for-{cve_id}",
            inputs=cve_id,
            expected_output=expected_output,
            evaluators=evaluators,
        )


class PromptLeakEvaluator(Evaluator[str, SuggestDescriptionModel]):
    @staticmethod
    def _match_re_in(pat, *args) -> bool:
        """look for regular expression pat (case insensitively) in the arguments"""
        for text in args:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _match_re_in_td(ctx, pat) -> bool:
        """look for regular expression pat (case insensitively) in title or description"""
        return PromptLeakEvaluator._match_re_in(
            pat,
            ctx.output.suggested_title,
            ctx.output.suggested_description,
        )

    async def evaluate(self, ctx) -> EvaluationReason:
        """check that text from the prompt template does not leak into the response"""

        # a list of unwanted regular expressions we chek for
        check_list = [
            r"'component.name'",
            r"\[impact\]",
            r"\[vector\]",
        ]

        # go through the list of regexes one by one
        for r in check_list:
            if self._match_re_in_td(ctx, r):
                return make_eval_reason(
                    fail_reason=f'"{r}" appears in title or description'
                )

        # no match
        return EvaluationReason(True)


async def suggest_description(cve_id: CVEID) -> SuggestDescriptionModel:
    """use rh_feature_agent to suggest description for the given CVE"""
    feature = SuggestDescriptionText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestDescriptionCase(
        # not vetted by a PSIRT analyst
        cve_id="CVE-2025-5399",
        expected_title="WebSocket endless loop",
        expected_description="A flaw was found in libcurl. This vulnerability allows a denial of service via a crafted WebSocket packet from a malicious server.",
    ),
    SuggestDescriptionCase(
        # not vetted by a PSIRT analyst
        cve_id="CVE-2025-23395",
        expected_title="Local Root Exploit via `logfile_reopen()`",
        expected_description="A flaw was found in Screen. When running with setuid-root privileged, the  logfile_reopen() function does not drop privileges while operating on a user-supplied path. This vulnerability allows an unprivileged user to create files in arbitrary locations with root ownership.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2002-1001",
        expected_title="tokio-tar:  parses PAX extended headers incorrectly, allows file smuggling",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2020-92465",
        expected_title="Django: Denial of service via Unicode input",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2022-23125",
        expected_title="Netatalk: Remote Code Execution via Buffer Overflow in copyapplfile function",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2023-39326",
        expected_description="A flaw was found in the Golang net/http/internal package. This issue may allow a malicious user to send an HTTP request and cause the receiver to read more bytes from network than are in the body (up to 1GiB), causing the receiver to fail reading the response, possibly leading to a Denial of Service (DoS).",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2023-53624",
        expected_description="An integer overflow vulnerability was found in network scheduler in the Linux kernel. In this flaw a denial of service problem is observed if sch_fq is configured to a higher value to INT_MAX.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2023-53669",
        expected_title="DoS in skb_copy_ubufs() caused by TCP tx zerocopy using hugepages with skb length bigger than ~68 KB",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-12816",
        expected_title="node-forge: Interpretation conflict vulnerability allows bypassing cryptographic verifications",
        expected_description="A flaw was found in node-forge. This vulnerability allows unauthenticated attackers to bypass downstream cryptographic verifications and security decisions via crafting ASN.1 (Abstract Syntax Notation One) structures to desynchronize schema validations, yielding a semantic divergence.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-13204",
        expected_description="A prototype pollution flaw was found in expr-eval. An attacker with access to express eval interface can use JavaScript prototype-based inheritance model to achieve arbitrary code execution.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-13327",
        expected_description="A flaw was found in uv. This vulnerability allows an attacker to execute malicious code during package resolution or installation via specially crafted ZIP (Zipped Information Package) archives that exploit parsing differentials, requiring user interaction to install an attacker-controlled package.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-13609",
        expected_description="A vulnerability has been identified in keylime where an attacker can exploit this flaw by registering a new agent using a different Trusted Platform Module (TPM) device but claiming an existing agent's unique identifier (UUID). This action overwrites the legitimate agent's identity, enabling the attacker to impersonate the compromised agent and potentially bypass security controls.",
    ),
    # FIXME: `suggest-description` should not talk about `Denial of Service`
    # SuggestDescriptionCase(
    #     cve_id="CVE-2025-37798",
    #     expected_description="FIXME",
    # ),
    # FIXME: clarify the expected_description for this evaluation case with a security analyst
    # SuggestDescriptionCase(
    #     cve_id="CVE-2025-21494",
    #     expected_description="This vulnerability allows an unauthenticated attacker to cause a hang or frequently repeatable crash via logon to the infrastructure where MySQL Server executes.",
    # ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-54770",
        expected_description="A vulnerability has been identified in the GRUB2 bootloader's network module that poses an immediate Denial of Service (DoS) risk. This flaw is a Use-after-Free issue, caused because the net_set_vlan command is not properly unregistered when the network module is unloaded from memory. An attacker who can execute this command can force the system to access memory locations that are no longer valid. Successful exploitation leads directly to system instability, which can result in a complete crash and halt system availability.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-60876",
        expected_title="BusyBox wget: CRLF Injection via unsanitized HTTP request-target allows header injection",
        expected_description="A flaw was found in BusyBox wget. This vulnerability allows an attacker to inject arbitrary Hypertext Transfer Protocol (HTTP) headers by failing to sanitize raw Carriage Return (CR) (0x0D), Line Feed (LF) (0x0A), and other C0 control bytes in the HTTP request-target.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-61661",
        expected_description="A vulnerability has been identified in the GRUB (Grand Unified Bootloader) component. This flaw occurs because the bootloader mishandles string conversion when reading information from a USB device, allowing an attacker to exploit inconsistent length values. A local attacker can connect a maliciously configured USB device during the boot sequence to trigger this issue. A successful exploitation may lead GRUB to crash, leading to a Denial of Service. Data corruption may be also possible, although given the complexity of the exploit the impact is most likely limited.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-63811",
        expected_description="A flaw was found in jose2go. This vulnerability allows an attacker to cause a Denial-of-Service (DoS).",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-64434",
        expected_description="A flaw was found in KubeVirt. This vulnerability allows API identity spoofing, compromising integrity and availability of managed VMs via improper TLS certificate management handling after compromising a virt-handler instance.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-64503",
        expected_title="cups-filters: Out-of-bounds write via crafted PDF MediaBox",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-64524",
        expected_description="A flaw was found in cups-filters. This vulnerability allows a heap buffer overflow and memory corruption, potentially leading to arbitrary code execution, via an unvalidated length parameter in the CompressData function of the rastertopclx filter. This can be exploited by an attacker with permissions to install a printer with a PPD (PostScript Printer Description) file or remotely via the CUPS (Common Unix Printing System) web interface. Additionally a Denial-of-Service may be triggered due to a segmentation fault when writing out-of-bounds, compromising the availability of the CUPS service.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-64756",
        expected_title="A flaw was found in glob. This vulnerability allows arbitrary command execution via processing files",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-65073",
        expected_description="A flaw was found in OpenStack Keystone. This vulnerability allows an attacker to obtain a valid OpenStack's Keystone token, leading to access to unauthorized resources or privilege escalation within the OpenStack instance via sending a valid AWS (Amazon Web Services) signature to the /v3/ec2tokens or /v3/s3tokens API (Application Programming Interface) endpoints.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-66448",
        expected_description="A remote code execution vulnerability has been identified in vLLM. An attacker can exploit a weakness in the model loading process to silently fetch and run unauthorized, malicious Python code on the host system. This happens because the engine mistakenly executes code from a remote repository referenced in a model's configuration, even when explicit security measures are set to prevent it.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2025-91735",
        expected_description="A flaw was found in /driver/xyz.c in xyg sub component in the Linux kernel. This vulnerability allows a buffer overflow due to xyz leading to abc.",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2099-99999",
        expected_title="ksmbd: Recursive Locking Denial of Service",
    ),
    SuggestDescriptionCase(
        cve_id="CVE-2099-232323",
        expected_description="A flaw was found in Keycloak. This vulnerability allows to trigger phishing attacks via error_description injection on error pages.",
    ),
]

# evaluators
evals = common_feature_evals + [
    PromptLeakEvaluator(),
    create_llm_judge(
        assertion_name="NoVersionInfo",
        rubric="suggested_title and suggested_description do not contain versions of affected components, except in acronyms explanation and in acronyms themselves.  Do not confuse API endpoint versions with component versions.",
    ),
    create_llm_judge(
        assertion_name="TitleSummarizesDescription",
        rubric="suggested_title briefly summarizes what is described in suggested_description",
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_description():
    """suggest_description evaluation entry point"""
    await run_evaluation(cases, evals, suggest_description)
