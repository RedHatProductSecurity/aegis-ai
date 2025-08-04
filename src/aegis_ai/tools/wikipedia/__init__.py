import logging
import wikipedia
from typing import List, Optional, Literal
from dataclasses import dataclass

from pydantic import BaseModel, Field

from pydantic_ai import (
    RunContext,
    Tool,
)

from aegis_ai.tools import BaseToolOutput

logger = logging.getLogger(__name__)


@dataclass
class WikipediaDependencies:
    test = 1


class GetWikipediaSoftwareInfoInput(BaseModel):
    """Input schema for the get_wikipedia_software_info tool."""

    component_name: str = Field(
        ...,
        description="The name of the software component (e.g., 'Apache Struts', 'Log4j', 'TensorFlow').",
    )


class WikipediaSoftwareInfo(BaseToolOutput):
    """
    Structured information retrieved about a software component from Wikipedia.
    Note: This does NOT include vulnerability or license data like SCA tools.
    """

    query_component_name: str = Field(
        ..., description="The original component name used in the query."
    )
    wikipedia_page_title: str = Field(
        ..., description="The exact title of the Wikipedia page found."
    )
    wikipedia_page_url: str = Field(..., description="The URL of the Wikipedia page.")
    summary: str = Field(
        ..., description="A concise summary of the software component from Wikipedia."
    )
    sections: List[str] = Field(
        default_factory=list,
        description="A list of top-level section titles within the Wikipedia page.",
    )
    status: Literal["success", "not_found", "disambiguation", "error"] = Field(
        ..., description="The status of the Wikipedia information retrieval."
    )
    error_message: Optional[str] = Field(
        None,
        description="An error message if the status is 'not_found', 'disambiguation', or 'error'.",
    )


@Tool
def wikipedia_tool(
    ctx: RunContext[WikipediaDependencies], input: GetWikipediaSoftwareInfoInput
) -> WikipediaSoftwareInfo:
    """
    Retrieves general encyclopedic information about a software component from Wikipedia
    based on its name. This tool provides high-level summaries and page links,
    but does NOT provide specific version details, vulnerability information (CVEs),
    license data, or dependency graphs. It is suitable for understanding
    the general nature and history of a software project.
    """
    component_name = input.component_name
    logger.info(f"wikipedia_lookup(component_name='{component_name}')")

    try:
        search_results = wikipedia.search(component_name)

        if not search_results:
            return WikipediaSoftwareInfo(
                query_component_name=component_name,
                wikipedia_page_title="",
                wikipedia_page_url="",
                summary=f"No Wikipedia page found for search term: '{component_name}'.",
                sections=[],
                status="not_found",
                error_message=f"No Wikipedia page found for '{component_name}'.",
            )

        # Attempt to get the page content for the first search result.
        try:
            page = wikipedia.page(search_results[0], auto_suggest=False)
        except wikipedia.DisambiguationError as e:
            # Handle disambiguation explicitly
            return WikipediaSoftwareInfo(
                query_component_name=component_name,
                wikipedia_page_title=e.options[
                    0
                ],  # Take the first option for simplicity
                wikipedia_page_url="",  # Cannot get URL without a specific page
                summary=f"'{component_name}' is ambiguous. Possible pages include: {', '.join(e.options[:5])}. "
                f"Returning info for the first option: '{e.options[0]}'. Please be more specific if needed.",
                sections=[],
                status="disambiguation",
                error_message=f"Ambiguous query. Options: {e.options}",
            )
        except wikipedia.PageError:
            # This might happen if the first search result is somehow invalid or redirects to nowhere
            return WikipediaSoftwareInfo(
                query_component_name=component_name,
                wikipedia_page_title="",
                wikipedia_page_url="",
                summary=f"Wikipedia page for '{component_name}' not found directly after search.",
                sections=[],
                status="not_found",
                error_message=f"Page not found for '{component_name}' or first search result was invalid.",
            )

        # Extract and return structured information
        return WikipediaSoftwareInfo(
            query_component_name=component_name,
            wikipedia_page_title=page.title,
            wikipedia_page_url=page.url,
            summary=page.summary,
            sections=[s for s in page.sections],
            status="success",
        )

    except Exception as e:
        return WikipediaSoftwareInfo(
            query_component_name=component_name,
            wikipedia_page_title="",
            wikipedia_page_url="",
            summary=f"An unexpected error occurred: {e}",
            sections=[],
            status="error",
            error_message=str(e),
        )
