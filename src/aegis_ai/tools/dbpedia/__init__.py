import logging
from typing import List, Optional, Literal

from pydantic import BaseModel, Field
from pydantic_ai import RunContext, Tool
from SPARQLWrapper import (
    SPARQLWrapper,
    JSON,
)  # Make sure you have this: pip install SPARQLWrapper


# In your project, you'd import this from your base module.
class BaseToolOutput(BaseModel):
    """Base model for all tool outputs."""

    pass


logger = logging.getLogger(__name__)


class GetDBpediaSoftwareInfoInput(BaseModel):
    """Input schema for the get_dbpedia_software_info tool."""

    component_name: str = Field(
        ...,
        description="The name of the software component (e.g., 'Apache Struts', 'Log4j', 'TensorFlow'). "
        "This name will be converted to a DBpedia resource.",
    )


class DBpediaSoftwareInfo(BaseToolOutput):
    """
    Structured information retrieved about a software component from DBpedia.
    This provides factual, structured data extracted from Wikipedia infoboxes.
    """

    query_component_name: str = Field(
        ..., description="The original component name used in the query."
    )
    dbpedia_resource_uri: str = Field(
        ...,
        description="The canonical DBpedia resource URI (Uniform Resource Identifier).",
    )
    abstract: Optional[str] = Field(
        None,
        description="The abstract/summary of the component from DBpedia (in English).",
    )
    homepage: Optional[str] = Field(
        None, description="The official homepage URL, if available."
    )
    programming_languages: List[str] = Field(
        default_factory=list,
        description="A list of programming languages associated with the component.",
    )
    # --- FIXED: Added missing fields to the model ---
    developers: List[str] = Field(
        default_factory=list,
        description="A list of developers or developing organizations.",
    )
    licenses: List[str] = Field(
        default_factory=list, description="A list of associated software licenses."
    )
    latest_releases: List[str] = Field(
        default_factory=list,
        description="A list of latest stable release versions or identifiers.",
    )
    # -----------------------------------------------
    status: Literal["success", "not_found", "error"] = Field(
        ..., description="The status of the DBpedia query."
    )
    error_message: Optional[str] = Field(
        None, description="An error message if the status is 'not_found' or 'error'."
    )


@Tool
def dbpedia_tool(
    ctx: RunContext,
    input: GetDBpediaSoftwareInfoInput,
) -> DBpediaSoftwareInfo:
    """
    Retrieves structured, factual data about a software component from the DBpedia
    SPARQL endpoint. This tool is excellent for finding specific facts like the
    project homepage or programming languages. It complements the Wikipedia tool,
    which provides unstructured summaries. This tool does NOT provide vulnerability or license data.
    """
    component_name = input.component_name
    logger.info(f"dbpedia_lookup(component_name='{component_name}')")

    resource_name = component_name.replace(" ", "_")
    resource_uri = f"http://dbpedia.org/resource/{resource_name}"

    endpoint_url = "https://dbpedia.org/sparql"

    sparql_query = f"""
PREFIX dbr: <http://dbpedia.org/resource/>
PREFIX dbo: <http://dbpedia.org/ontology/>
PREFIX foaf: <http://xmlns.com/foaf/0.1/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT 
    ?abstract 
    ?homepage
    (GROUP_CONCAT(DISTINCT ?langLabel; SEPARATOR=", ") AS ?programming_languages)
    (GROUP_CONCAT(DISTINCT ?devLabel; SEPARATOR=", ") AS ?developers)
    (GROUP_CONCAT(DISTINCT ?licLabel; SEPARATOR=", ") AS ?license)
    (GROUP_CONCAT(DISTINCT ?releaseVersion; SEPARATOR=", ") AS ?latest_releases)
WHERE {{
    BIND(dbr:{resource_name} AS ?resource)
    OPTIONAL {{ 
        ?resource dbo:abstract ?abstract . 
        FILTER(langMatches(lang(?abstract), "en"))
    }}
    OPTIONAL {{ ?resource foaf:homepage ?homepage . }}

    OPTIONAL {{
        ?resource dbo:programmingLanguage ?lang .
        ?lang rdfs:label ?langLabel .
        FILTER(langMatches(lang(?langLabel), "en"))
    }}
    OPTIONAL {{
        ?resource dbo:developer ?dev .
        ?dev rdfs:label ?devLabel .
        FILTER(langMatches(lang(?devLabel), "en"))
    }}
    OPTIONAL {{
        ?resource dbo:license ?lic .
        ?lic rdfs:label ?licLabel .
        FILTER(langMatches(lang(?licLabel), "en"))
    }}
    OPTIONAL {{ ?resource dbo:latestStableRelease ?releaseVersion . }}
}}
GROUP BY ?abstract ?homepage
LIMIT 1
"""

    try:
        sparql = SPARQLWrapper(endpoint_url)
        sparql.setQuery(sparql_query)
        sparql.setReturnFormat(JSON)
        sparql.setTimeout(10)

        results = sparql.query().convert()
        bindings = results.get("results", {}).get("bindings", [])

        if not bindings:
            return DBpediaSoftwareInfo(
                query_component_name=component_name,
                dbpedia_resource_uri=resource_uri,
                status="not_found",
                error_message=f"No data found in DBpedia for resource: {resource_uri}",
            )

        data = bindings[0]

        # Helper function to parse the comma-separated strings from GROUP_CONCAT
        def parse_concat(field_data: dict) -> List[str]:
            val = field_data.get("value", "")
            return [item.strip() for item in val.split(",") if item.strip()]

        # Use the correct keys from the SPARQL query aliases
        languages = parse_concat(data.get("programming_languages", {}))
        devs = parse_concat(data.get("developers", {}))
        lics = parse_concat(data.get("license", {}))
        releases = parse_concat(data.get("latest_releases", {}))

        # Pass all parsed data to the output model
        return DBpediaSoftwareInfo(
            query_component_name=component_name,
            dbpedia_resource_uri=resource_uri,
            abstract=data.get("abstract", {}).get("value"),
            homepage=data.get("homepage", {}).get("value"),
            programming_languages=languages,
            developers=devs,
            licenses=lics,
            latest_releases=releases,
            status="success",
        )

    except Exception as e:
        logger.error(f"DBpedia SPARQL query failed for '{component_name}': {e}")
        return DBpediaSoftwareInfo(
            query_component_name=component_name,
            dbpedia_resource_uri=resource_uri,
            status="error",
            error_message=f"SPARQL query failed: {str(e)}",
        )
