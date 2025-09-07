import logging

from aegis_ai.features import Feature
from aegis_ai.features.component.data_models import (
    ComponentIntelligenceModel,
    ComponentFeatureInput,
)
from aegis_ai.prompt import AegisPrompt

logger = logging.getLogger(__name__)


class ComponentIntelligence(Feature):
    """Based on supplied component name and rh context generate a component 'card' of information."""

    async def exec(self, component_name):
        prompt = AegisPrompt(
            user_instruction="Your task is to meticulously examine the provided context (eg. component name or purl) and generate a 'card' of information about the software component.",
            goals="""
                * Given a software component, identified by full or partial package name with (or without version) or more specific pURL, provide a brief description of the software component (200 words).
                * Identify the latest release version of the software component by consulting git repos, release notes or software package management systems.
                * Find the software component primary website
                * Rank the software component's popularity based on usage and ubiquity on a scale of 1 to 10  (1 being most widely used and 10 being hardly used at all). If the software component has a git repo use its 'likes' or 'stars' (for github) to help assess popularity.
                * Rank the software component's stability  (1 to 10, 1 being very stable and 10 being unstable) - a project is stable if it is actively maintained, has many contributors, and has well defined development and security processes. If the software component has a github repo, having a large queue of issues which span many years can indicate worst stability.
                * Identify approximate number of CVEs the component already has.
                * Identify number of known exploits the component has/
                * Find and present recent news related to the component (in the past year).
                * List the most active contributors (with affiliations) to the software component in a bulleted format. Use sites like GitStats to assess the most active contributors.
                * Identify the repository location of the component.
                * List other (most popular) software components which include this software component as a dependency.
                * Provide topical, critical security information related to the software component.
                * Include a few links to tutorials, readme and docs
                * Identify and enumerate which Red Hat products include the software component            
            """,
            rules="""
                1.  Information Gathering:
                    * When provided with a package name and version or pURL, initiate a search for relevant software component information. This includes looking in wikipedia, dbpedia or other software package management sites.
                    * Check as many sources as possible to confirm latest software component release version ... most likely this will be in the year 2025 - do not show version if you are not confident it is latest.
                    * describe the component, programming language, primary architecture and features, latest version number
                    * Prioritize up-to-date sources for news and security vulnerabilities.
                    * if available always use dbpedia tool to get structured context on the project/component.
                    * if available always use wikipedia tool to get unstructured context on the project/component.
                    * if available always use github mcp tool to retrieve information on the project/component.
                    * if available and component is in python ecosystem then use mcp pypi tool to lookup more context.
                    * if available check with cisakev tool for exploits on the component.
                    * Identify and extract key information regarding the component's description, recent activities, contributors and what companies they work for (and affiliations), repository, and security status.
                    * list any other popular software components that may include the component name in its name
                    * Investigate and report on any outstanding security issues of any listed dependencies. Provide web links if appropriate.
                    * when analyzing hackerone reports should be careful to classify based on response to the report from creator of software - a hackerone report that was closed without assigning a severity should be ignored.
                2.  Output Formatting:
                    * first line should include component name and latest version in bold with release date (ex. component name (v1.0 released on 01.01.2025)  )
                    * second line should include popularity and stability rank (ex. popularity: 1, stability: 1)
                    * third line should just include software component website
                    * fourth line should just include repository location (ex. repository-url: https://example.org)
                    * fifth line should include pURL
                    * Present the component's description concisely.
                    * Format recent news as a bulleted list with any reference links.
                    * Clearly state the names of the most active contributors (with affiliations).
                    * Provide a direct link or clear indication of the repository location.
                    * Present critical security information in a clear and understandable manner.
                    * For dependencies, clearly label their security information separately.
                    * Further learning section should include links to tutorials and docs
            """,
            context=ComponentFeatureInput(component_name=component_name),
            output_schema=ComponentIntelligenceModel.model_json_schema(),
        )
        logger.debug(prompt.to_string())
        return await self.run_if_safe(prompt, output_type=ComponentIntelligenceModel)
