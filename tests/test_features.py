import pytest

from aegis.agents import rh_feature_agent
from aegis.features import component, cve

pytestmark = pytest.mark.asyncio


async def test_suggest_impact_with_test_model():
    result = await cve.SuggestImpact(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.SuggestImpactModel)


async def test_suggest_cwe_with_test_model():
    result = await cve.SuggestCWE(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.SuggestCWEModel)


async def test_identify_pii_with_test_model():
    result = await cve.IdentifyPII(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.PIIReportModel)


async def test_rewrite_description_with_test_model():
    result = await cve.RewriteDescriptionText(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.RewriteDescriptionModel)


async def test_rewrite_statement_with_test_model():
    result = await cve.RewriteStatementText(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.RewriteStatementModel)


async def test_cvss_diff_explain_with_test_model():
    result = await cve.CVSSDiffExplainer(rh_feature_agent).exec("CVE-2025-0725")
    assert isinstance(result.output, cve.data_models.CVSSDiffExplainerModel)


async def test_component_intelligence_test_model():
    result = await component.ComponentIntelligence(rh_feature_agent).exec("curl")
    assert isinstance(result.output, component.data_models.ComponentIntelligenceModel)
