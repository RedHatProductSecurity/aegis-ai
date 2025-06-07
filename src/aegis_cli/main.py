"""
aegis cli

"""

import json
from typing import List, Dict

import click
import asyncio

from rich.console import Console
from rich.rule import Rule

from pydantic import Field
from pydantic_ai.agent import AgentRunResult

from aegis import check_llm_status, config_logging
from aegis.agents import (
    component_feature_agent,
    feature_agent,
    chat_agent,
)
from aegis.features import component, cve
from aegis.features.data_models import AegisAnswer
from aegis.rag import (
    add_fact_to_vector_store,
    FactInput,
    initialize_rag_db,
    DocumentInput,
    add_document_to_vector_store,
)

from aegis_cli import print_version

console = Console()


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

    if check_llm_status():
        pass
    else:
        exit(1)


@aegis_cli.command()
@click.argument("fact", type=str)
def add_fact(fact):
    """ """

    async def _doit():
        await initialize_rag_db()
        return await add_fact_to_vector_store(
            FactInput(fact=fact, metadata={"source": "aegis"})
        )

    result = asyncio.run(_doit())
    if result:
        console.print("fact added")


@aegis_cli.command()
@click.argument("file_path", type=str)
def add_document(file_path):
    """ """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json_data_dict = json.load(f)
            console.print(json.dumps(json_data_dict, indent=4))

            async def _doit():
                await initialize_rag_db()
                return await add_document_to_vector_store(
                    DocumentInput(
                        text=json.dumps(json_data_dict, indent=4),
                        metadata={"document_url": file_path},
                    )
                )

            result = asyncio.run(_doit())
            if result:
                console.print("fact added")

    except FileNotFoundError:
        console.print(f"Error: The file '{file_path}' was not found.")
    except json.JSONDecodeError:
        console.print(
            f"Error: Could not decode JSON from '{file_path}'. Check file format."
        )
    except Exception as e:
        console.print(f"An unexpected error occurred: {e}")


@aegis_cli.command()
@click.argument("query", type=str)
def search_norag(query):
    """
    Perform search query with no supplied context.
    """

    async def _doit():
        return await feature_agent.run(query)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("query", type=str)
def search(query):
    """
    Perform search query which has rag lookup tool providing context.
    """

    async def _doit():
        # await initialize_rag_db()
        return await chat_agent.run(query, output_type=AegisAnswer)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output)


@aegis_cli.command()
@click.argument("cve_id", type=str)
def identify_pii(cve_id):
    """
    Identify PII contained in CVE record.
    """

    async def _doit():
        feature = cve.IdentifyPII(feature_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=str)
def suggest_impact(cve_id):
    """
    Suggest overall impact of CVE.
    """

    async def _doit():
        feature = cve.SuggestImpact(feature_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=str)
def suggest_cwe(cve_id):
    """
    Suggest CWE.
    """

    async def _doit():
        feature = cve.SuggestCWE(feature_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=str)
def rewrite_description(cve_id):
    """
    Rewrite CVE description text.
    """

    async def _doit():
        feature = cve.RewriteDescriptionText(feature_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=str)
def rewrite_statement(cve_id):
    """
    Rewrite CVE statement text.
    """

    async def _doit():
        feature = cve.RewriteStatementText(feature_agent)
        return await feature.exec(cve_id)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


@aegis_cli.command()
@click.argument("cve_id", type=str)
def cvss_diff(cve_id):
    """
    CVSS Diff explainer.
    """

    async def _doit():
        feature = cve.CVSSDiffExplainer(feature_agent)
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
        feature = component.ComponentIntelligence(component_feature_agent)
        return await feature.exec(component_name)

    result = asyncio.run(_doit())
    if result:
        console.print(Rule())
        console.print(result.output.model_dump_json(indent=2))


class ChatResponse(AgentRunResult):
    """
    Structured response from the chatbot agent.
    """

    answer: str = Field(description="The generated answer to the user's query.")
    mood: str = Field(
        default="neutral",
        description="The detected mood of the chatbot's response (e.g., 'neutral', 'helpful', 'apologetic').",
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="A confidence score for the answer (0.0 to 1.0).",
    )


@aegis_cli.command()
def chat():
    """
    A simple AI chatbot CLI using pydantic-ai.

    """
    if not feature_agent:
        click.echo(
            click.style(
                "Error: Chatbot agent is not initialized. Please check logs for API key issues.",
                fg="red",
            )
        )
        return

    click.echo(click.style("\n--- Welcome to the AI Chatbot! ---", fg="bright_blue"))
    click.echo(
        click.style("Type 'exit' or 'quit' to end the conversation.", fg="bright_blue")
    )

    # Initialize conversation history
    # This list will hold messages in OpenAI API format: {"role": "user", "content": "...", "role": "assistant", "content": "..."}
    # The system prompt is already handled by the Agent's system_prompt parameter.
    conversation_history: List[Dict[str, str]] = []

    while True:
        try:
            user_input = click.prompt(
                click.style("\nYou: ", fg="cyan"), type=str, prompt_suffix=""
            )
            if user_input.lower() in ["exit", "quit"]:
                click.echo(click.style("--- Goodbye! ---", fg="bright_blue"))
                break

            click.echo(click.style("AI Thinking...", fg="yellow"), nl=False)
            agent_response = asyncio.run(
                feature_agent.run(user_input, messages=conversation_history)
            )
            conversation_history.append({"role": "user", "content": user_input})

            structured_response: ChatResponse = agent_response.output

            click.echo(click.style(f"\rAI {structured_response}", fg="green"))
            # Add AI's response to history for next turn
            conversation_history.append(
                {"role": "assistant", "content": structured_response}
            )

        except Exception as e:
            click.echo(
                click.style(f"\nError: Failed to get response from AI. {e}", fg="red")
            )
            # Optionally, remove the last user message if the AI failed to respond
            if conversation_history and conversation_history[-1]["role"] == "user":
                conversation_history.pop()
