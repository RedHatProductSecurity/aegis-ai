import logging
from typing import Optional

from aegis_ai.features import Feature
from aegis_ai.features.component.data_models import (
    ComponentIntelligenceModel,
    ComponentFeatureInput,
)
from aegis_ai.features.data_models import feature_deps
from aegis_ai.prompt import AegisPrompt

logger = logging.getLogger(__name__)


def _component_intelligence_goals(context: ComponentFeatureInput) -> str:
    if context.component_name:
        return """
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
                * List other (most popular) software components which include this software component as a dependency. Populate the output 'components' field with the requested component name.
                * Provide topical, critical security information related to the software component.
                * Include a few links to tutorials, readme and docs
                * Identify and enumerate which Red Hat products include the software component
            """
    else:
        return """
                * From the provided vulnerability title and description, identify the affected software component(s). Populate the output 'components' field with the list of component names (e.g. package names, project names). Set 'component_name' to the primary or first-listed component.
                * For the primary component, provide a brief description (200 words), latest release version, website, repository, popularity and stability ranks (1-10), CVE count, exploit count, recent news, active contributors, security information, further learning links, and which Red Hat products include it.
                * If multiple components are identified, focus the card on the primary one but list all in 'components'.
                * When a CVE ID is provided in context, use the OSIDB tool with that CVE ID to retrieve flaw data for this vulnerability (do not look up other CVE IDs from the description unless needed).
                * If the component is identified as being from the golang ecosystem and part of the standard library, dont use golang as the component name, find a more specific package name.
                * For golang components not in the standard library, include the namespace in the component, eg github.com/containerd/containerd instead of just containerd.
                * If the component is identified as being from the python standard library use 'python' as the component name.
            """


class ComponentIntelligence(Feature):
    """Based on component name or (title + description) generate a component 'card' and list of components."""

    async def exec(
        self,
        component_name: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        cve_id: Optional[str] = None,
    ):
        context = ComponentFeatureInput(
            component_name=component_name,
            title=title,
            description=description,
            cve_id=cve_id,
        )
        user_instruction = (
            "Your task is to meticulously examine the provided context and generate a 'card' of information about the software component."
            if context.component_name
            else "Your task is to identify the affected software component(s) from the provided vulnerability title and description, then generate a 'card' of information about the primary component."
        )
        prompt = AegisPrompt(
            user_instruction=user_instruction,
            goals=_component_intelligence_goals(context),
            rules="""
                1.  Information Gathering:
                    * When provided with a package name and version or pURL, initiate a search for relevant software component information. This includes looking in wikipedia or other software package management sites.
                    * When provided with title and description, extract affected component names (packages, libraries, projects) and list them in the output 'components' field; set component_name to the primary one.
                    * Check as many sources as possible to confirm latest software component release version ... most likely this will be in the year 2025 - do not show version if you are not confident it is latest.
                    * describe the component, programming language, primary architecture and features, latest version number
                    * Prioritize up-to-date sources for news and security vulnerabilities.
                    * if available use osidb component_flaw_tool to retrieve additional CVE information related to component
                    * if available always use wikipedia tool to get unstructured context on the project/component.
                    * if available always use github mcp tool to retrieve information on the project/component.
                    * if available and component is in python ecosystem then use mcp pypi tool to lookup more context.
                    * if available check with cisakev tool for exploits on the component.
                    * Identify and extract key information regarding the component's description, recent activities, contributors and what companies they work for (and affiliations), repository, and security status.
                    * list any other popular software components that may include the component name in its name
                    * Investigate and report on any outstanding security issues of any listed dependencies. Provide web links if appropriate.
                    * when analyzing hackerone reports should be careful to classify based on response to the report from creator of software - a hackerone report that was closed without assigning a severity should be ignored.
                2.  Output Formatting:
                    * Always populate the 'components' output field: when given a component name, include that name plus any related components; when given title and description, list the identified affected component names.
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
            context=context,
            output_schema=ComponentIntelligenceModel.model_json_schema(),
        )
        logger.debug(prompt.to_string())
        # In title+description mode, exclude 'components' from OSIDB tool response so the
        # model must infer components from the text; in component_name mode, no exclusion.
        deps = feature_deps(
            exclude_osidb_fields=["components"] if not context.component_name else []
        )
        return await self.run_if_safe(
            prompt, deps=deps, output_type=ComponentIntelligenceModel
        )
