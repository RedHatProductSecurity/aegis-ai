"""
aegis cli

"""

import json
import logging
import sys

import click
import asyncio

from rich.console import Console
from rich.rule import Rule

from aegis_ai import check_llm_status, config_logging, get_settings
from aegis_ai.agents import (
    rh_feature_agent,
    public_feature_agent,
    simple_agent,
)
from aegis_ai.data_models import CVEID
from aegis_ai.features import component, cve
from aegis_ai.features.data_models import AegisAnswer

from aegis_ai_cli import print_version, feature_agent


def _load_context(context_str):
    """Load static context from a JSON file path, stdin ('-'), or inline JSON string."""
    if context_str is None:
        return None
    if context_str == "-":
        return json.load(sys.stdin)
    # Try as file path first
    try:
        with open(context_str) as f:
            return json.load(f)
    except OSError:
        pass
    # Fall back to inline JSON
    try:
        return json.loads(context_str)
    except json.JSONDecodeError as e:
        raise click.BadParameter(
            f"Could not parse --context as a file path or JSON string: {e}"
        )

console = Console()

if "public" in feature_agent:
    cli_agent = public_feature_agent
else:
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
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def identify_pii(cve_id, context_src):
    """
    Identify PII contained in CVE record.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.IdentifyPII(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def suggest_impact(cve_id, context_src):
    """
    Suggest overall impact of CVE.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.SuggestImpact(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def suggest_cwe(cve_id, context_src):
    """
    Suggest CWE.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.SuggestCWE(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def suggest_description(cve_id, context_src):
    """
    Suggest CVE description text.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.SuggestDescriptionText(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def suggest_statement(cve_id, context_src):
    """
    Suggest CVE statement text.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.SuggestStatementText(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
@click.option("--context", "-c", "context_src", default=None, help="Static context as a JSON file path, inline JSON string, or '-' for stdin.")
def cvss_diff(cve_id, context_src):
    """
    CVSS Diff explainer.
    """
    static_context = _load_context(context_src)

    async def _doit():
        feature = cve.CVSSDiffExplainer(cli_agent)
        return await feature.exec(cve_id, static_context=static_context)

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
