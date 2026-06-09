"""
aegis cli

"""

import logging

import click
import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from aegis_ai import check_llm_status, config_logging, get_settings
from aegis_ai.data_models import CVEID
from aegis_ai.features import component, cve
from aegis_ai.features.data_models import AegisAnswer

from aegis_ai_cli import print_version, feature_agent

console = Console()

if "public" in feature_agent:
    from aegis_ai.agents import public_feature_agent

    cli_agent = public_feature_agent
else:
    from aegis_ai.agents import rh_feature_agent

    cli_agent = rh_feature_agent


@click.group()
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Display griffon version.",
)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
def aegis_cli(debug):
    """Top level click entrypoint"""

    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    logging.info(f"Aegis version: {get_settings().app_version}")
    logging.info(f"Aegis cli_agent: {cli_agent.name}")

    if check_llm_status():
        pass
    else:
        exit(1)


@aegis_cli.command()
@click.argument("query", type=str)
def search_plain(query):
    """
    Perform search query with no supplied context.
    """

    async def _doit():
        from aegis_ai.agents import simple_agent

        return await simple_agent.run(query, output_type=AegisAnswer)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output)


@aegis_cli.command()
@click.argument("query", type=str)
def search(query):
    """
    Perform search query which has rag lookup tool providing context.
    """

    async def _doit():
        # await initialize_rag_db()
        return await public_feature_agent.run(query, output_type=AegisAnswer)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output)


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def identify_pii(cve_id):
    """
    Identify PII contained in CVE record.
    """

    async def _doit():
        feature = cve.IdentifyPII(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


def _build_diagnostics(output) -> dict:
    """Extract pipeline diagnostics from a SuggestImpactModel into a plain dict."""
    data: dict = {}

    orig_impact = output._original_llm_impact
    orig_score = output._original_llm_score
    orig_vector = output._original_llm_vector
    if orig_impact or orig_score:
        data["llm_raw_assessment"] = {
            "impact": orig_impact,
            "score": orig_score,
            "vector": orig_vector,
        }

    diag = output._classifier_diagnostics
    if diag and isinstance(diag, dict):
        data["kernel_classifier"] = {
            "xgboost_prediction": diag.get("raw_prediction"),
            "after_cascade": diag.get("impact"),
            "confidence": diag.get("confidence"),
            "probabilities": diag.get("probabilities"),
            "external_cvss_score": diag.get("cvss_score"),
            "external_cvss_issuer": diag.get("cvss_issuer"),
            "patches_analyzed": diag.get("patches_analyzed"),
        }
        active = diag.get("active_features")
        if active:
            data["patch_flags"] = sorted(active)
            html_supp = diag.get("html_supplemented_flags")
            if html_supp:
                data["html_supplemented_flags"] = sorted(html_supp)

    trace = output._reconciliation_trace
    if trace:
        data["reconciliation_trace"] = trace

    data["post_processing"] = {
        "impact_changed": orig_impact != output.impact if orig_impact else False,
        "original_impact": orig_impact,
        "final_impact": output.impact,
        "explanation_revised": output._explanation_revised,
    }

    return data


def _print_impact_diagnostics(output) -> None:
    """Render verbose pipeline diagnostics for a SuggestImpactModel."""
    data = _build_diagnostics(output)
    lines: list[str] = []

    llm_raw = data.get("llm_raw_assessment")
    if llm_raw:
        lines.append("[bold]LLM Raw Assessment[/bold]")
        lines.append(
            f"  Impact: {llm_raw['impact'] or '?'} | Score: {llm_raw['score'] or '?'}"
            f" | Vector: {llm_raw['vector'] or '?'}"
        )
        lines.append("")

    clf = data.get("kernel_classifier")
    if clf:
        lines.append("[bold]Kernel Classifier[/bold]")
        lines.append(
            f"  XGBoost prediction: {clf['xgboost_prediction'] or '?'}"
            f" | After cascade rules: {clf['after_cascade'] or '?'}"
        )
        conf = clf.get("confidence") or 0.0
        lines.append(f"  Confidence: {conf:.2f}")

        probs = clf.get("probabilities")
        if probs and isinstance(probs, dict):
            prob_parts = [f"{k}={v:.2f}" for k, v in probs.items()]
            lines.append(f"  Probabilities: {'  '.join(prob_parts)}")

        ext_score = clf.get("external_cvss_score")
        if ext_score:
            issuer = clf.get("external_cvss_issuer") or ""
            issuer_str = f" ({issuer})" if issuer else ""
            lines.append(f"  External CVSS: {ext_score}{issuer_str}")

        patches = clf.get("patches_analyzed")
        if patches is not None:
            lines.append(f"  Patches analyzed: {patches}")
        lines.append("")

    flags = data.get("patch_flags")
    if flags:
        lines.append("[bold]Patch Flags[/bold]")
        lines.append(f"  {', '.join(flags)}")
        html_supp = data.get("html_supplemented_flags")
        if html_supp:
            lines.append(f"  (HTML-supplemented: {', '.join(html_supp)})")
        lines.append("")

    trace = data.get("reconciliation_trace")
    if trace:
        lines.append("[bold]Reconciliation[/bold]")
        for part in trace.split("; "):
            lines.append(f"  {part}")
        lines.append("")

    pp = data["post_processing"]
    lines.append("[bold]Post-Processing[/bold]")
    if pp["impact_changed"]:
        lines.append(
            f"  Impact changed: {pp['original_impact']} -> {pp['final_impact']}"
        )
    else:
        lines.append("  Impact unchanged")
    lines.append(
        f"  Explanation revised: {'yes' if pp['explanation_revised'] else 'no'}"
    )

    panel = Panel(
        Text.from_markup("\n".join(lines)),
        title="Pipeline Diagnostics",
        border_style="dim",
    )
    console.print(panel)


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option(
    "--verbose", "-v", is_flag=True, help="Show detailed pipeline diagnostics."
)
@click.option(
    "--include-diagnostics",
    "include_diagnostics",
    is_flag=True,
    help="Include pipeline diagnostics in JSON output.",
)
def suggest_impact(cve_id, verbose, include_diagnostics):
    """
    Suggest overall impact of CVE.
    """

    async def _doit():
        feature = cve.SuggestImpact(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        if include_diagnostics:
            import json

            output_dict = json.loads(result.output.model_dump_json())
            output_dict["diagnostics"] = _build_diagnostics(result.output)
            console.print(json.dumps(output_dict, indent=2))
        else:
            console.print(result.output.model_dump_json(indent=2))
        if verbose and not include_diagnostics:
            _print_impact_diagnostics(result.output)


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def suggest_cwe(cve_id):
    """
    Suggest CWE.
    """

    async def _doit():
        feature = cve.SuggestCWE(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def suggest_description(cve_id):
    """
    Suggest CVE description text.
    """

    async def _doit():
        feature = cve.SuggestDescriptionText(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def suggest_statement(cve_id):
    """
    Suggest CVE statement text.
    """

    async def _doit():
        feature = cve.SuggestStatementText(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def cvss_diff(cve_id):
    """
    CVSS Diff explainer.
    """

    async def _doit():
        feature = cve.CVSSDiffExplainer(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def quality_review(cve_id):
    """
    Review quality of CVE flaw content against a weighted quality rubric (0.0-1.0 scale).
    """

    async def _doit():
        """Execute the quality review feature asynchronously."""
        feature = cve.QualityReview(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def suggest_affected_components(cve_id):
    """
    Suggest affected components for a CVE.
    """

    async def _doit():
        feature = cve.SuggestAffectedComponents(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("component_name", type=str)
def component_intelligence(component_name):
    """
    Component intelligence.
    """

    async def _doit():
        feature = component.ComponentIntelligence(public_feature_agent)
        return await feature.exec(component_name)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.option(
    "--state-file",
    type=click.Path(),
    default=None,
    help="Path to state file.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Skip flaw eligibility validation.",
)
@click.option(
    "--read-only",
    is_flag=True,
    default=False,
    help="Skip OSIDB data updates (dry run).",
)
@click.argument("cve_ids", nargs=-1, type=CVEID)
def osidb_bot(state_file, force, read_only, cve_ids):
    """
    OSIDB bot: process CVE IDs (optional) with optional state file.
    """
    # lazy import to speed up basic Aegis CLI operations
    from aegis_ai.osidb_bot import Bot, StateFileHandler, logger
    from aegis_ai.osidb_bot.util import log_memory

    # avoid logging tracebacks when GSSAPI auth fails
    logging.getLogger("requests_gssapi").setLevel(logging.CRITICAL)

    log_memory("cli_entry")

    try:
        # this prevents multiple processes running in parallel on a single state file
        # (if state_file is not None)
        with StateFileHandler(state_file) as sfh:
            osidb_bot = Bot(sfh, cli_agent, force=force, read_only=read_only)
            log_memory("bot_created")
            runner = osidb_bot.process(cve_ids)
            asyncio.run(runner)
    except RuntimeError as e:
        logger.error(str(e))
