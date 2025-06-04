import pytest
from pydantic_ai.models.test import TestModel

from aegis.agents import feature_agent
from aegis.features import component, cve


def test_test():
    assert 1 == 1


@pytest.mark.asyncio
async def test_suggest_impact_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.SuggestImpact(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.SuggestImpactModel)


@pytest.mark.asyncio
async def test_suggest_cwe_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.SuggestCWE(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.SuggestCWEModel)


@pytest.mark.asyncio
async def test_identify_pii_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.IdentifyPII(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.PIIReportModel)


@pytest.mark.asyncio
async def test_rewrite_description_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.RewriteDescriptionText(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.RewriteDescriptionModel)


@pytest.mark.asyncio
async def test_rewrite_statement_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.RewriteStatementText(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.RewriteStatementModel)


@pytest.mark.asyncio
async def test_cvss_diff_explain_with_test_model():
    with feature_agent.override(model=TestModel()):
        result = await cve.CVSSDiffExplainer(feature_agent).exec("CVE-2025-0725")
        assert isinstance(result.output, cve.data_models.CVSSDiffExplainerModel)


@pytest.mark.asyncio
async def test_component_intelligence_test_model():
    with feature_agent.override(model=TestModel()):
        result = await component.ComponentIntelligence(feature_agent).exec("curl")
        assert isinstance(
            result.output, component.data_models.ComponentIntelligenceModel
        )
