import logging

from aegis.features import env_fs, Feature
from aegis.features.cve.data_models import (
    CVSSDiffExplainerModel,
    SuggestImpactModel,
    SuggestCWEModel,
    PIIReportModel,
    RewriteStatementModel,
    RewriteDescriptionModel,
)

logger = logging.getLogger(__name__)


class SuggestImpact(Feature):
    """Based on current CVE information and context assert an aggregated impact."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/suggest_impact_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": SuggestImpactModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=SuggestImpactModel)


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/suggest_cwe_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": SuggestCWEModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=SuggestCWEModel)


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/identify_pii_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": PIIReportModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=PIIReportModel)


class RewriteDescriptionText(Feature):
    """Based on current CVE information and context rewrite/create description and title."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/rewrite_description_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": RewriteDescriptionModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=RewriteDescriptionModel)


class RewriteStatementText(Feature):
    """Based on current CVE information and context rewrite/create statement."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/rewrite_statement_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": RewriteStatementModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=RewriteStatementModel)


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id):
        template = env_fs.get_template("cve/cvss_diff_explainer_prompt.txt")
        prompt = template.render(
            {
                "cve_id": cve_id,
                "schema": CVSSDiffExplainerModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=CVSSDiffExplainerModel)
