import logging
import os
import pytest

from pydantic_ai.tools import RunContext, Tool
from pydantic_ai.toolsets import CombinedToolset, FunctionToolset

from aegis_ai import config_logging
from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools.osidb import CVE, cve_exclude_fields, OSIDBToolInput
from aegis_ai.toolsets.tools.osv_dev_cve import OSVToolInput as OSVCVEToolInput
from aegis_ai.toolsets.tools.osv_dev_ghsa import (
    GHSAToolInput,
    extract_ghsa_ids,
    _filter_osv_response,
)
import aegis_ai.toolsets as ts

from evals.features.common import eval_metrics, eval_summary
from evals.utils.kernel_cve_context_cache import (
    cache_misses,
    kernel_cve_cache_lookup,
    write_misses_report,
)
from evals.utils.kernel_patch_cache import (
    cached_fetch_commit_html,
    cached_fetch_patches,
    html_cache_misses,
    patch_cache_misses,
    write_patch_cache_misses_report,
)
from evals.utils.external_references_cache import (
    cache_misses as extref_cache_misses,
    extref_cache_retrieve,
    write_misses_report as write_extref_misses_report,
)
from evals.utils.ghsa_cache import (
    cache_misses as ghsa_cache_misses,
    ghsa_cache_retrieve,
    write_misses_report as write_ghsa_misses_report,
)
from evals.utils.osidb_cache import osidb_cache_retrieve


@Tool
async def osidb_tool(ctx: RunContext[feature_deps], input: OSIDBToolInput) -> CVE:
    """wrapper around aegis.tools.osidb that caches OSIDB responses"""
    cve = await osidb_cache_retrieve(input.cve_id)
    return cve_exclude_fields(
        cve,
        ctx.deps.exclude_osidb_fields,
        strip_component_prefix_for_osidb_cache=True,
    )


@Tool
async def osv_dev_ghsa_tool(ctx: RunContext, input: GHSAToolInput):
    """wrapper around osv_dev_ghsa that caches OSV.dev responses"""
    ghsa_ids = extract_ghsa_ids(input.references)
    if not ghsa_ids:
        return []
    results = []
    for ghsa_id in ghsa_ids:
        raw = await ghsa_cache_retrieve(ghsa_id)
        filtered = _filter_osv_response(raw)
        if filtered:
            results.append(filtered)
    return results


@Tool
async def osv_dev_cve_tool(ctx: RunContext, input: OSVCVEToolInput):
    """wrapper around osv_dev_cve that caches OSV.dev responses"""
    return await ghsa_cache_retrieve(str(input.cve_id))


# pytest's built-in monkeypatch fixture is function-scoped, so session-scoped
# fixtures cannot depend on it.  We need a session-wide MonkeyPatch because the
# cache patches below (_patch_cve_retrieve, _patch_kernel_cve_lookup, etc.) must
# survive the entire eval run, not just a single test function.
@pytest.fixture(scope="session")
def _monkeypatch_session():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="session", autouse=True)
def _patch_cve_retrieve(_monkeypatch_session):
    """Route ALL cve_retrieve calls through the OSIDB cache during evals.

    The agent toolset swap (override_rh_feature_agent) only intercepts LLM
    tool calls.  Code that calls cve_retrieve directly — e.g. the kernel
    classifier's _fetch_osidb_cvss — would still hit live OSIDB without this.
    """
    import aegis_ai.toolsets.tools.osidb as osidb_mod

    _monkeypatch_session.setattr(osidb_mod, "cve_retrieve", osidb_cache_retrieve)


@pytest.fixture(scope="session", autouse=True)
def _patch_kernel_cve_lookup(_monkeypatch_session):
    """Route kernel_cve_lookup through a local JSON cache during evals.

    Both kernel_cve_tool (LLM tool call) and kernel_impact_classify (pre-
    classifier) resolve kernel_cve_lookup from the kernel_cves module at call
    time, so patching the module attribute intercepts both paths and avoids
    git clone/pull of the upstream linux security vulns repo.
    """
    import aegis_ai.toolsets.tools.kernel_cves as kernel_cves_mod

    _monkeypatch_session.setattr(
        kernel_cves_mod, "kernel_cve_lookup", kernel_cve_cache_lookup
    )


@pytest.fixture(scope="session", autouse=True)
def _patch_kernel_patch_fetch(_monkeypatch_session):
    """Route patch/HTML fetches through the disk cache during evals.

    Closes the R1 violation: ``_fetch_patches`` and ``_fetch_commit_html``
    would otherwise make live HTTP requests to git.kernel.org and GitHub.
    The cache is populated offline by ``populate_kernel_cve_cache.py``.
    """
    from aegis_ai.kernel_classifier import KernelImpactClassifier

    _monkeypatch_session.setattr(
        KernelImpactClassifier, "_fetch_patches", cached_fetch_patches
    )
    _monkeypatch_session.setattr(
        KernelImpactClassifier, "_fetch_commit_html", cached_fetch_commit_html
    )


@pytest.fixture(scope="session", autouse=True)
def _patch_external_references(_monkeypatch_session):
    """Route external reference fetches through disk cache during evals."""
    import aegis_ai.toolsets.tools.external_references as extref_mod

    _monkeypatch_session.setattr(extref_mod, "fetch_reference", extref_cache_retrieve)


# enable logging to see progress
@pytest.fixture(scope="session", autouse=True)
def setup_logging_for_session():
    level = "DEBUG" if logging.getLogger().isEnabledFor(logging.DEBUG) else "INFO"
    config_logging(level=level)

    # Suppress noisy httpx/httpcore request logs during eval runs only
    for noisy_logger in ("httpx", "httpx._client", "httpcore"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    # Suppress the "[tool call] ..." logs ONLY during eval runs
    class _SuppressToolCallFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            try:
                msg = record.getMessage()
            except Exception:
                return True
            return not msg.startswith("[tool call] ")

    # Skip suppression of logged tool during evals if user explicitly enables
    #  verbose logging via env var
    if not os.getenv("AEGIS_LOGGING_EVALS_VERBOSE"):
        logging.getLogger("aegis_ai.toolsets").addFilter(_SuppressToolCallFilter())


# Cache OSIDB responses (maintained in git) so evals are invariant to
# future OSIDB data changes.
@pytest.fixture(scope="session", autouse=True)
def override_osidb_toolset():
    cached = FunctionToolset[feature_deps](tools=[osidb_tool])
    wrapped = ts.redhat_cve_toolset.wrapped
    if isinstance(wrapped, CombinedToolset):
        wrapped.toolsets[0] = cached  # type:ignore


@pytest.fixture(scope="session", autouse=True)
def override_public_cve_toolset():
    cached = FunctionToolset(tools=[osv_dev_cve_tool, osv_dev_ghsa_tool])
    wrapped = ts.public_cve_toolset.wrapped
    if isinstance(wrapped, CombinedToolset):
        wrapped.toolsets[0] = cached  # type:ignore


# Optionally exit successfully if ${AEGIS_EVALS_MIN_PASSED} tests have succeeded
def pytest_sessionfinish(session, exitstatus):
    # print evaluation summary for each feature
    for feat, summary in eval_summary.items():
        logging.info(f"[{feat}] {summary}")

        metrics = eval_metrics[feat]
        if not metrics:
            # the metrics might not be available if all cases failed
            continue

        # print evaluation score for each evaluator and average duration for each feature
        for eval_name, score in metrics.scores.items():
            logging.info(f"[{feat}] {eval_name}: {score:.4f}")

        evaluator_duration = metrics.total_duration - metrics.task_duration
        logging.info(f"[{feat}] assertions ratio: {metrics.assertions * 100:.1f}%")
        logging.info(f"[{feat}] average case duration: {metrics.task_duration:.2f}s")
        logging.info(f"[{feat}] average evaluator duration: {evaluator_duration:.2f}s")

    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if not tr:
        return

    min_passed = os.getenv("AEGIS_EVALS_MIN_PASSED")
    if min_passed:
        # get the actual count of passed tests
        passed = tr.stats.get("passed")
        num_passed = 0
        if passed:
            excluded = ["setup", "teardown"]
            num_passed = sum(1 for t in passed if t.when not in excluded)

        if int(min_passed) <= num_passed:
            # make pytest exit successfully
            session.exitstatus = pytest.ExitCode.OK

    misses_file = write_misses_report()
    if misses_file:
        logging.warning(
            "[kernel_cve_context_cache] %d cache miss(es) written to %s — "
            "run populate_kernel_cve_cache.py to fill them",
            len(cache_misses),
            misses_file,
        )

    patch_misses_file = write_patch_cache_misses_report()
    if patch_misses_file:
        total = len(patch_cache_misses) + len(html_cache_misses)
        logging.warning(
            "[kernel_patch_cache] %d cache miss(es) written to %s — "
            "run populate_kernel_cve_cache.py to fill them",
            total,
            patch_misses_file,
        )

    ghsa_misses_file = write_ghsa_misses_report()
    if ghsa_misses_file:
        logging.warning(
            "[ghsa_cache] %d cache miss(es) written to %s — "
            "commit the new evals/ghsa_cache/*.json files",
            len(ghsa_cache_misses),
            ghsa_misses_file,
        )

    extref_misses_file = write_extref_misses_report()
    if extref_misses_file:
        logging.warning(
            "[external_references_cache] %d cache miss(es) written to %s — "
            "commit the new evals/external_references_cache/*.json files",
            len(extref_cache_misses),
            extref_misses_file,
        )

    logging.info(f"[pytest] exit status: {session.exitstatus}")
