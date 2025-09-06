"""
aegis cli

"""

import logging

import click
import asyncio

from rich.console import Console
from rich.rule import Rule

from aegis_ai import check_llm_status, config_logging
from aegis_ai.agents import (
    rh_feature_agent,
    public_feature_agent,
    simple_agent,
)
from aegis_ai.data_models import CVEID
from aegis_ai.features import component, cve
from aegis_ai.features.data_models import AegisAnswer

from aegis_ai_cli import print_version, feature_agent

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


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def suggest_impact(cve_id):
    """
    Suggest overall impact of CVE.
    """

    async def _doit():
        feature = cve.SuggestImpact(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


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
def rewrite_description(cve_id):
    """
    Rewrite CVE description text.
    """

    async def _doit():
        feature = cve.RewriteDescriptionText(cli_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=CVEID)
def rewrite_statement(cve_id):
    """
    Rewrite CVE statement text.
    """

    async def _doit():
        feature = cve.RewriteStatementText(cli_agent)
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
