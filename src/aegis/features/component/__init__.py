import logging
from typing import Literal
from pydantic import BaseModel, Field

from jinja2 import (
    Environment,
    FileSystemLoader,
    PackageLoader,
    Template,
    exceptions as jinja2_exceptions,
)

from aegis.features import env_fs, Feature
from aegis.features.cve.data_models import (
    SuggestImpactModel,
    SuggestCWEModel,
    PIIReportModel,
    RewriteStatementModel,
    RewriteDescriptionModel,
)

from aegis.features import Feature

from aegis.features.component.data_models import ComponentIntelligenceModel

logger = logging.getLogger(__name__)


class ComponentIntelligence(Feature):
    async def exec(self, component_name):
        template = env_fs.get_template("component/component_intelligence_prompt.txt")
        prompt = template.render(
            {
                "context": component_name,
                "schema": ComponentIntelligenceModel.model_json_schema(),
            }
        )
        logger.debug(prompt)
        return await self.agent.run(prompt, output_type=ComponentIntelligenceModel)
