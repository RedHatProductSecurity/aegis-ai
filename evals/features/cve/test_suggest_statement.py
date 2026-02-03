import pytest
from typing import get_args

from pydantic_evals import Case

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features.cve import (
    SuggestStatementText,
    SuggestStatementModel,
)

from evals.features.common import (
    common_feature_evals,
    create_llm_judge,
    run_evaluation,
)

# some evaluators are only applicable if the expected output for a specific field is provided
field_evaluators = {
    "suggested_statement": create_llm_judge(
        score_name="StatementEvaluator",
        rubric=(
            "Score semantic equivalence between the actual suggested_statement and the expected suggested_statement. "
            "Emphasize matching rationale (impact justification in RH context, preconditions, scope). "
            "If style differs but the core message overlaps, the score should be > 0.0 and < 1.0 depending on overlap. "
            "Only assign 0.0 if the actual is irrelevant to the CVE or contradicts the expected meaning. "
            "When partially aligned but missing details, prefer a low non-zero score (e.g., 0.12–0.3) rather than 0.0."
        ),
        include_expected_output=True,
    ),
    "suggested_mitigation": create_llm_judge(
        score_name="MitigationEvaluator",
        rubric="Score how much the actual suggested_mitigation field is semantically equivalent to the expected suggested_mitigation field.  If the key message is the same but the style is different, the score should not be zero.  If the style is different, the score should not be 1.0.",
        include_expected_output=True,
    ),
}


class SuggestStatementCase(Case):
    def __init__(
        self, cve_id, expected_statement=None, expected_mitigation=None, **kwargs
    ):
        """cve_id given as CVE-YYYY-NUM is the flaw we suggest statement/mitigation for."""
        disclaimer_model = SuggestStatementModel.model_fields["disclaimer"]
        disclaimer = get_args(disclaimer_model.annotation)[0]
        expected_output = SuggestStatementModel(
            cve_id=cve_id,
            title="",
            impact="",
            components=[],
            description="",
            explanation="",
            suggested_statement=expected_statement,
            suggested_mitigation=expected_mitigation,
            confidence=1.0,
            tools_used=[],
            disclaimer=disclaimer,
        )

        # enable field-specific evaluators for this case
        evaluators = tuple(
            field_evaluators[f]
            for f in field_evaluators
            if getattr(expected_output, f) is not None
        )

        super().__init__(
            name=f"suggest-statement-for-{cve_id}",
            inputs=cve_id,
            expected_output=expected_output,
            evaluators=evaluators,
            **kwargs,
        )


async def suggest_statement(cve_id: CVEID) -> SuggestStatementModel:
    """use rh_feature_agent to suggest statement for the given CVE"""
    feature = SuggestStatementText(rh_feature_agent)
    result = await feature.exec(cve_id)
    return result.output


# test cases
cases = [
    SuggestStatementCase(
        cve_id="CVE-2022-1012",
        expected_statement="""Red Hat Enterprise Linux version 7 (RHEL7) is not affected by this issue. While RHEL7 implements the TCP port randomization algorithm 3 (the Simple Hash-Based Port Selection Algorithm), which knowingly has shortcomings (as per RFC 6056, item 3.3.3), the object of study of this flaw was the TCP port selector algorithm 4, the Double-Hash Port Selection Algorithm, which is not existent in RHEL7.
            This flaw is ranked as a Moderate impact due to:
            * Limited exposure of the data in the TCP stack;
            * The impact of this vulnerability is limited to a system fingerprinting;
            * The requirements to carry the attack are elevated, requiring monitoring of the data flow.
            """,
        expected_mitigation="""Mitigation for this issue is either not available or the currently available options don't meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base, or stability.""",
    ),
    SuggestStatementCase(
        cve_id="CVE-2022-50087",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 8 and 9. A use-after-free flaw in the `arm_scpi` firmware component of the Linux kernel could allow a local attacker to escalate privileges. ",
    ),
    SuggestStatementCase(
        cve_id="CVE-2022-50390",
        expected_statement="This vulnerability is rated Low for Red Hat. The flaw in the Linux kernel's drm/ttm component, specifically an undefined behavior in bit shifting, could lead to local information disclosure and denial of service. This vulnerability could theoretically affect integrity, though it is unlikely and non-deterministic. Similarly, availability may be affected as the flaw can result in a kernel warning or panic. ",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    # NOTE: After merging https://github.com/RedHatProductSecurity/aegis-ai/pull/370
    # LLM does not get the correct answer on its input from the `mitigation` field
    # in the `osidb_cache` data.  However, the correct answer is still provided to LLM
    # from a public comment in `osdib_cache`.  So we are not exercising here anything
    # complex or very practical.
    SuggestStatementCase(
        cve_id="CVE-2023-48795",
        expected_statement="""This CVE is classified as moderate because the attack requires an active Man-in-the-Middle (MITM) who can intercept and modify the connection's traffic at the TCP/IP layer.
    Although the attack is cryptographically innovative, its security impact is fortunately quite limited. It only allows the deletion of consecutive messages, and deleting most messages at this protocol stage prevents user authentication from proceeding, leading to a stalled connection.
    The most significant identified impact is that it enables a MITM to delete the SSH2_MSG_EXT_INFO message sent before authentication begins. This allows the attacker to disable a subset of keystroke timing obfuscation features. However, there is no other observable impact on session secrecy or session integrity.""",
        expected_mitigation="""Update to the last version and check that client and server provide kex pseudo-algorithms indicating usage of the updated version of the protocol which is protected from the attack. If "kex-strict-c-v00@openssh.com" is provided by clients and "kex-strict-s-v00@openssh.com" is in the server's reply, no other steps are necessary.
        Disabling ciphers if necessary:

        If "kex-strict-c-v00@openssh.com" is not provided by clients or "kex-strict-s-v00@openssh.com" is absent in the server's reply, you can disable the following ciphers and HMACs as a workaround on RHEL-8 and RHEL-9:

        1. chacha20-poly1305@openssh.com
        2. hmac-sha2-512-etm@openssh.com
        3. hmac-sha2-256-etm@openssh.com
        4. hmac-sha1-etm@openssh.com
        5. hmac-md5-etm@openssh.com

        To do that through crypto-policies, one can apply a subpolicy with the following content:
        ```
        cipher@SSH = -CHACHA20-POLY1305
        ssh_etm = 0
        ```
        e.g., by putting these lines into `/etc/crypto-policies/policies/modules/CVE-2023-48795.pmod`, applying the resulting subpolicy with `update-crypto-policies --set $(update-crypto-policies --show):CVE-2023-48795` and restarting openssh server.

        One can verify that the changes are in effect by ensuring the ciphers listed above are missing from both `/etc/crypto-policies/back-ends/openssh.config` and `/etc/crypto-policies/back-ends/opensshserver.config`.

        For more details on using crypto-policies https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening

        This procedure does limit the interoperability of the host and is only suggested as a temporary mitigation until the issue is fully resolved with an update.

        For RHEL-7:
        We can recommend to use strict MACs and Ciphers on RHEL7 in both files /etc/ssh/ssh_config and /etc/ssh/sshd_config.

        Below strict set of Ciphers and MACs can be used as mitigation for RHEL 7.

        ```
        Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
        MACs umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512
        ```

        - For Openshift Container Platform 4:
        KCS[1] document for verifying the fix in RHCOS.

        [1] https://access.redhat.com/solutions/7071748""",
    ),
    SuggestStatementCase(
        cve_id="CVE-2023-53176",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux. A privileged local attacker (ex. with `CAP_SYS_ADMIN` privileges) could cause a denial of service by unbinding a serial port hardware-specific 8250 driver, leading to a kernel oops.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2023-53188",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux. A race condition in the Open vSwitch kernel module can lead to a denial of service, causing a CPU to become stuck in an infinite loop. Exploitation requires a specific setup involving Open vSwitch, veth pairs, and concurrent deletion of network namespaces while traffic is active; these actions require elevated privileges such as `CAP_NET_ADMIN`. Attack complexity is similarly high, since triggering this vulnerability requires a specific timing window, sustained parallel traffic, and a namespace teardown. The only meaningful impact from successfully causing the vulnerability is to availability. No data leakage, memory disclosure, or information exposure is involved, and there is no evidence of memory corruption. ",
    ),
    SuggestStatementCase(
        cve_id="CVE-2023-53205",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux on the s390x architecture. The flaw is a race condition in the KVM s390/diag handler that could lead to out-of-bounds access. Triggering this vulnerability requires precise timing and repeated invocations and will most likely result in a denial-of-service. Confidentiality is not impacted as the bug does not directly expose guest or host memory contents. Availability is also highly unlikely to be impacted, though out-of-bounds access could in theory corrupt the kernel or KVM internal state. ",
        metadata={"known_to_fail_evaluators": ["StatementNoDuplicatedInfo"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2023-53333",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux. The flaw is a stack-out-of-bounds read in the netfilter DCCP connection tracking module. Exploitation requires an attacker to send specially crafted DCCP packets to a system with the `nf_conntrack_dccp` module loaded. The vulnerability's impact is primarily on availability, since a malformed packet can lead to a warning or panic, though it can also pose a potential (though unlikely) risk to confidentiality, since kernel stack values could be exposed indirectly through side channels or other error-dependent behaviors. ",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2023-54108",
        expected_statement="This vulnerability is rated Low for Red Hat Enterprise Linux 8 and 9. The flaw in the `qla2xxx` SCSI driver can lead to a DMA-API call trace, potentially impacting system availability. This issue affects systems utilizing QLogic Fibre Channel HBAs with NVMe LS requests. Triggering this vulnerability affects availability, though it will not typically crash the kernel, but more likely degrade system stability or flood logs. ",
    ),
    SuggestStatementCase(
        cve_id="CVE-2024-44308",
        expected_statement="""In order to exploit this vulnerability, the WebKitGTK JIT engine must be enabled and an attacker needs to trick a user into processing or loading malicious web content.  This feature is disabled in Red Hat Enterprise Linux versions 8 and 9, meaning these releases are not affected by this vulnerability.
            """,
        expected_mitigation="""Do not process or load untrusted web content with WebKitGTK.
            Affected installations of Red Hat Enterprise Linux 7 can disable the JIT engine by setting the JavaScriptCoreUseJIT environment variable to 0.
            Additionally, in Red Hat Enterprise Linux 7, the following packages require WebKitGTK4: evolution-data-server, glade, gnome-boxes, gnome-initial-setup, gnome-online-accounts, gnome-shell, shotwell, sushi and yelp.
            This vulnerability can only be exploited when these packages are installed in the system and being used via a graphical interface to process untrusted web content, via GNOME for example. In gnome-shell, the vulnerability can be exploited by an attacker from the local network without user interaction.
            To mitigate this vulnerability, consider removing these packages. Note that some of these packages are required by GNOME, removing them will also remove GNOME and other packages, breaking functionality. However, the server can still be used via the terminal interface.
            Additionally, WebKitGTK3 is not required by any package. Therefore, it can be removed without consequences or break of functionality.
            """,
    ),
    SuggestStatementCase(
        cve_id="CVE-2024-53197",
        expected_statement="""This CVE marked as important vulnerability because it allows a malicious or compromised USB device to trigger out-of-bounds memory accesses in the Linux kernel’s ALSA USB audio subsystem. This occurs due to improper handling of bNumConfigurations, which can lead to memory corruption or even privilege escalation if exploited. Since USB devices can be dynamically plugged in, an attacker with physical access could potentially exploit this flaw to execute arbitrary code in kernel space or cause a system crash.
            Because the kernel supports virtual USB devices, this vulnerability could still be exploited by an attacker without physical access, but is able to create virtual USB devices which use the vulnerable device drivers.
            """,
        expected_mitigation="""To mitigate this issue, prevent module snd-usb-audio from being loaded.
            As the snd_usb_audio module will be auto-loaded when a usb device is hot plugged, the module can be prevented by loading with the following instructions:
            # echo "install snd_usb_audio /bin/true" >> /etc/modprobe.d/disable-snd-usb-audio.conf
            The system will need to be restarted if the modules are loaded. In most circumstances, the sound kernel modules will be unable to be unloaded while any programs are active and the device are in use.
            If the system requires this module to work correctly, this mitigation may not be suitable.
            If you need further assistance, see KCS article https://access.redhat.com/solutions/41278 or contact Red Hat Global Support Services.
            """,
        metadata={
            "known_to_fail_evaluators": ["MitigationEvaluator", "StatementEvaluator"]
        },
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-5399",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-8677",
        expected_statement="""This vulnerability is considered Important because it allows a remote, unauthenticated attacker to cause significant CPU exhaustion on vulnerable BIND resolvers by serving zones containing malformed DNSKEY records. The flaw triggers excessive computational effort during DNSKEY validation, leading to degraded performance and potential denial of service for legitimate clients. However, the issue affects availability only—it does not enable code execution, data exposure, or privilege escalation—so it is not classified as critical. Furthermore, authoritative servers are not impacted, limiting the scope of exposure to recursive resolvers. While the attack is easy to launch and can disrupt DNS operations, its effect ceases once the malicious traffic stops and recursive access control effective mitigations.""",
        expected_mitigation="""Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.
            To reduce risk, restrict recursive queries to trusted or internal networks only, and apply rate limiting or firewall rules to prevent excessive or repetitive requests. Enabling DNSSEC validation helps reject forged records, while isolating recursive resolvers from authoritative servers limits the impact of potential cache poisoning. Active monitoring of CPU usage, query volume, and cache anomalies can provide early warning of abuse or attacks.""",
        metadata={
            "known_to_fail_evaluators": [
                "MitigationEvaluator",
                "StatementNoDuplicatedInfo",
            ]
        },
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-9222",
        expected_statement="...rated Important.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-12816",
        expected_statement="This vulnerability is rated Important for Red Hat products due to an interpretation conflict in the node-forge library. An unauthenticated attacker could exploit this flaw by crafting malicious ASN.1 structures, leading to a bypass of cryptographic verifications and security decisions in affected applications. This impacts various Red Hat products that utilize node-forge for cryptographic operations.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-13327",
        expected_statement="This vulnerability is rated Moderate for Red Hat products. It allows arbitrary code execution through specially crafted ZIP archives when using the `uv` tool to install attacker-controlled Python packages. Exploitation requires user interaction to initiate the package installation. This affects components within Red Hat AI Inference Server and Red Hat OpenShift AI.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-15284",
        expected_statement="This vulnerability is rated Important for Red Hat products that utilize the `qs` module for parsing query strings, particularly when processing user-controlled input with bracket notation. The `arrayLimit` option, intended to prevent resource exhaustion, is bypassed when bracket notation (`a[]=value`) is used, allowing a remote attacker to cause a denial of service through memory exhaustion. This can lead to application crashes or unresponsiveness, making the service unavailable.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-22097",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-23395",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-29781",
        expected_statement="""This vulnerability is rated as Important for OpenShift Baremetal Operator, because RBAC is cluster-scoped and, while WATCH_NAMESPACE is set to openshift-machine-api by default, it is common for deployments to have a less restrictive value configured. It breaks Kubernetes' namespace isolation by allowing a user to create a BMCEventSubscription that references Secrets from unauthorized namespaces. In OpenShift, where Secrets often store high-value assets like kubeadmin credentials or cloud API keys, this enables unauthorized access to sensitive data across tenant boundaries. It effectively becomes a horizontal privilege escalation vector, allowing a namespace-scoped user to exfiltrate secrets intended for other components or tenants.  Given the minimal exploit complexity and high-impact potential, especially in multi-tenant environments, this issue is more severe than a moderate flaw and justifies a high CVSS rating.
        """,
        expected_mitigation="""Operator can configure BMO role-based access control (RBAC) to be namespace scoped instead of cluster scoped to prevent BMO from accessing Secrets from other namespaces, or use the `WATCH_NAMESPACE` configuration option to limit BMO to a single namespace.
        """,
    ),
    # FIXME: The actual suggested_statement indicates the vulnerability is 'Important for Red Hat' and some products are 'under investigation'
    SuggestStatementCase(
        cve_id="CVE-2025-30706",
        expected_statement="No Red Hat products are affected by this vulnerability.",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-32463",
        expected_statement="""The severity of this vulnerability is rated as Important due to the requirement that an attacker must have access to a valid account on a system and that it allows a local unprivileged attacker to escalate their privileges even if the account is not listed in the sudoers file.
        """,
        expected_mitigation="""Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.
        """,
        metadata={"known_to_fail_evaluators": ["MitigationEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-38512",
        expected_statement="This vulnerability in the Linux kernel's Wi-Fi component allows an adjacent attacker to perform A-MSDU spoofing attacks in mesh networks, leading to a high integrity impact. Confidentiality could potentially be impacted, if there is exposure of network\u2011internal traffic or services via the spoofed Ethernet frames. Similarly, availability may be impacted if the spoofed packets cause problems like traffic disruption or routing instabilities.",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39791",
        expected_statement="This vulnerability is rated Moderate for Red Hat, as it can lead to a kernel deadlock or file system data corruption (xfs or btrfs) when using dm-crypt with zoned targets. This flaw primarily targets Integrity and Availability as incorrect sector reporting during zone append operations can lead to corrupt filesystem metadata as well as I/O hangs or system stalls.",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39795",
        expected_statement="This vulnerability is rated Low for Red Hat Enterprise Linux because a possible integer overflow in the `blk_stack_limits()` function within the kernel's block layer could be exploited by an attacker with high privileges. Successful exploitation may lead to a denial of service or information disclosure. Triggering this vulnerability requires elevated privileges (ex. `CAP_SYS_ADMIN`) as modifying or creating block stacks is a privileged operation. If the bug is triggered, then there are potentially impacts to integrity and availability, in that a misalignment could result in an incorrect write to storage which in turn could cause some I/O errors, though they are unlikely to hang the system outright.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39809",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 9, 10, and Red Hat In-Vehicle OS 1. The flaw, a stack-out-of-bounds in the `intel_quicki2c` kernel module, can lead to a kernel crash due to improper handling of ACPI DSD method lengths. Red Hat Enterprise Linux 6, 7, and 8 are not affected as the vulnerable code is not present in these versions. If triggered, this vulnerability only affects integrity and availability, as the stack-out-of-bounds overwrite could affect adjacent local variables (even if the overwrite is of one byte) and malformed or affected acpi tables could lead to a kernel crash. There is no reason to assume confidentiality is impacted, as the vulnerability is of a write nature, and not a read.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39810",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 8 and 9. A memory corruption flaw exists in the `bnxt_en` kernel driver, which could be triggered when firmware resources change during an interface down operation. Triggering this vulnerability requires elevated privileges (ex. `CAP_NET_ADMIN`) as configuring traffic classes is a privileged operation. If the vulnerability is triggered, then the primary impact will be on integrity and availability, as the bug can cause kernel memory corruption in the kernel heap structures related to network i/o, which in turn can lead to a kernel crash. Confidentiality is most probably not impacted, as an out-of-bounds write could overwrite adjacent kernel memory, but no direct read exposure is implied.\n\nRed Hat Enterprise Linux 6, 7, and Red Hat In-Vehicle OS are not affected as the vulnerable code is not present in these versions.",
        metadata={
            "known_to_fail_evaluators": [
                "StatementEvaluator",
                "StatementNoDuplicatedInfo",
            ]
        },
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39816",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 10.x. The flaw exists in the io_uring/kbuf component of the kernel, where improper handling of ring provided buffer lengths from userspace could lead to an issue. Red Hat Enterprise Linux 6, 7, 8, and 9 are not affected as the vulnerable code is not present in these versions. If triggered, this vulnerability affects integrity and availability, as the bug can cause inconsistent internal states and lead to stalls or system instability in the io_uring subsystem.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39822",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 10 as it could lead to a local privilege escalation due to a signedness error in the io_uring subsystem. Red Hat Enterprise Linux 6, 7, 8, and 9 are not affected as the vulnerable code is not present in these versions. If triggered, this vulnerability can lead to integrity and availability issues, as an improperly computed `this_len` could lead to memory corruption, data truncation, or incorrect writes, which in turn could increase the likelihood of a crash. ",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-39832",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux 9 and 10. The flaw in the `net/mlx5` driver could lead to a kernel lockdep assertion during a synchronous reset unload event, specifically when using the `devlink reload fw_activate` option. This issue affects systems utilizing Mellanox network adapters and performing firmware activation reloads. Triggering this vulnerability requires elevated privileges and primarily impacts availability, as it can lead to kernel warnings or firmware failures.",
        metadata={"known_to_fail_evaluators": ["StatementNoDuplicatedInfo"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-43529",
        expected_statement="This vulnerability is rated IMPORTANT for Red Hat products. A use-after-free flaw in webkitgtk, when processing maliciously crafted web content, can lead to remote code execution. Successful exploitation requires user interaction, where a victim must visit a malicious website.",
        expected_mitigation="To mitigate this issue, avoid processing untrusted web content. Additionally, disabling the JavaScript JIT compiler can reduce the attack surface. For applications using WebKitGTK, set the environment variable `JavaScriptCoreUseJIT=0` before launching the application. This may impact performance for JavaScript-heavy web content.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-59088",
        expected_statement="I didn't have an expected value, but I expected that the suggested statement would include supporting information that I might have missed. But the result seems to just rephrase the flaw description and was off on the impact. The flaw impact was rated Important, while the suggestion rated it a critical.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-64503",
        expected_statement="This vulnerability is rated Moderate for Red Hat Enterprise Linux because a specially crafted PDF file, when processed by the `cups-filters` `pdftoraster` tool, can lead to an out-of-bounds write, potentially causing a denial of service. This affects Red Hat Enterprise Linux 7, 8, 9, and 10.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-64524",
        expected_statement="Red Hat rates this Moderate. While the `rastertopclx` filter runs under the `lp` user, limiting direct root compromise, the vulnerability can be exploited remotely via the CUPS web interface by an attacker with low privileges to install a printer with a crafted PPD file. This could lead to a denial of service or potentially arbitrary code execution, impacting system availability.",
        expected_mitigation='To reduce exposure, restrict network access to the CUPS service (port 631) to trusted hosts only using firewall rules. For example, using `firewall-cmd`: `firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" source address="<TRUSTED_IP_ADDRESS>" port port="631" protocol="tcp" accept\'` `firewall-cmd --reload` Alternatively, if printing services are not required, disable the CUPS service: `systemctl stop cups` `systemctl disable cups` Note that disabling CUPS will prevent all printing functionality on the system. If firewall rules are applied, ensure they are persistent across reboots.',
    ),
    # FIXME: security analysts expect statement to be empty in this case
    SuggestStatementCase(
        cve_id="CVE-2025-64527",
        expected_statement="",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-66623",
        expected_statement="This vulnerability is rated Important for Red Hat AMQ Streams. Affected Strimzi versions 0.47.0 through 0.49.0 create an incorrect Kubernetes Role, granting Apache Kafka Connect and Apache Kafka MirrorMaker 2 operands unauthorized GET access to all Kubernetes Secrets within the operator's namespace. This could lead to sensitive information disclosure.",
        expected_mitigation="Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base or stability.",
        metadata={"known_to_fail_evaluators": ["MitigationEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-68469",
        expected_mitigation="To mitigate this issue, avoid processing untrusted TIFF files with ImageMagick. In environments where ImageMagick processes files automatically, ensure that all input files originate from trusted sources or implement strict input validation to prevent the processing of malicious TIFF files.",
    ),
    SuggestStatementCase(
        cve_id="CVE-2025-69262",
        expected_statement="This vulnerability is rated Moderate for Red Hat. The flaw in pnpm allows for remote code execution via command injection when environment variable substitution is used in `.npmrc` files with `tokenHelper` settings. Exploitation requires an attacker to control environment variables and place malicious scripts, primarily impacting build environments such as CI/CD pipelines or Docker builds. Red Hat products like Enterprise Application Platform are not directly affected by this pnpm vulnerability.",
        metadata={"known_to_fail_evaluators": ["StatementEvaluator"]},
    ),
    SuggestStatementCase(
        cve_id="CVE-2026-22822",
        expected_mitigation="To mitigate this issue, implement a policy engine such as Kubernetes, Kyverno, Kubewarden, or OPA. Configure the policy engine to prevent the usage of the `getSecretKey` function within any ExternalSecret resource. This will block the insecure cross-namespace secret retrieval capability.",
        metadata={"known_to_fail_evaluators": ["StatementNoDuplicatedInfo"]},
    ),
]

# evaluators
evals = common_feature_evals + [
    create_llm_judge(
        assertion_name="StatementDoNotSuggestPatch",
        rubric="The suggested_statement field does not suggest to apply a source code patch or rebuild the software.",
    ),
    create_llm_judge(
        assertion_name="StatementNoCodeLevelDetails",
        rubric="The suggested_statement field does not include any extensive code-level details about the flaw. Code constants or env variables are ok.",
    ),
    create_llm_judge(
        assertion_name="StatementNoDuplicatedInfo",
        rubric="A non empty suggested_statement field should not duplicate verbatim the CVE description. It is acceptable to provide some description when used to explain impact.",
    ),
    create_llm_judge(
        assertion_name="MitigationWellFormedCommands",
        rubric="The suggested_mitigation field should not contain invented config flags, incorrect environment variables - all commandline should be plausible.",
    ),
]

# needed for asyncio event loop
pytestmark = pytest.mark.asyncio(loop_scope="session")


async def test_eval_suggest_statement():
    """suggest_statement evaluation entry point"""
    await run_evaluation(cases, evals, suggest_statement)
