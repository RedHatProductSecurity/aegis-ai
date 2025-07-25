import pytest

from pydantic_core import ValidationError

from aegis_ai.agents import rh_feature_agent
from aegis_ai.data_models import CVEID
from aegis_ai.features import component, cve
from tests.utils.llm_cache import llm_cache_retrieve

pytestmark = pytest.mark.asyncio


async def test_suggest_impact_with_test_model():
    def feature():
        return cve.SuggestImpact(rh_feature_agent).exec("CVE-2025-0725")

    result = await llm_cache_retrieve(feature)
    suggestimpact = cve.data_models.SuggestImpactModel.model_validate_json(result)
    assert isinstance(suggestimpact, cve.data_models.SuggestImpactModel)
    assert suggestimpact.impact == "LOW"


async def test_suggest_cwe_with_test_model():
    def feature():
        return cve.SuggestCWE(rh_feature_agent).exec("CVE-2025-0725")

    result = await llm_cache_retrieve(feature)
    suggestcwe = cve.data_models.SuggestCWEModel.model_validate_json(result)
    assert isinstance(suggestcwe, cve.data_models.SuggestCWEModel)
    assert suggestcwe.cwe == ["CWE-190", "CWE-120"]


async def test_identify_pii_with_test_model():
    def feature():
        cve_id = CVEID(
            "CVE-2025-0725"
        )  # we can directly use custom fields though auto validation happens during feature input
        return cve.IdentifyPII(rh_feature_agent).exec(cve_id)

    result = await llm_cache_retrieve(feature)
    piireport = cve.data_models.PIIReportModel.model_validate_json(result)
    assert isinstance(piireport, cve.data_models.PIIReportModel)
    assert not piireport.contains_PII  # is false


async def test_rewrite_description_with_test_model():
    def feature():
        return cve.RewriteDescriptionText(rh_feature_agent).exec("CVE-2025-0725")

    result = await llm_cache_retrieve(feature)
    rewritedescription = cve.data_models.RewriteDescriptionModel.model_validate_json(
        result
    )
    assert isinstance(rewritedescription, cve.data_models.RewriteDescriptionModel)
    assert (
        rewritedescription.rewritten_title
        == "libcurl: integer overflow in zlib decompression"
    )


async def test_rewrite_statement_with_test_model():
    def feature():
        return cve.RewriteStatementText(rh_feature_agent).exec("CVE-2025-0725")

    result = await llm_cache_retrieve(feature)
    rewritestatement = cve.data_models.RewriteStatementModel.model_validate_json(result)
    assert isinstance(rewritestatement, cve.data_models.RewriteStatementModel)
    assert (
        rewritestatement.rewritten_statement
        == "A flaw was found in libcurl, where a buffer overflow could be triggered. This issue occurs when libcurl, using a vulnerable version of the zlib library (1.2.0.3 or older), performs automatic gzip decompression of content-encoded HTTP responses. A malicious server could exploit this by sending a specially crafted response, causing an integer overflow in zlib that leads to a buffer overflow in libcurl, resulting in a denial of service. Red Hat Enterprise Linux is not affected by this vulnerability as it does not ship the vulnerable version of zlib. However, some Red Hat products that bundle the affected library may be impacted."
    )


async def test_cvss_diff_explain_with_test_model():
    def feature():
        return cve.CVSSDiffExplainer(rh_feature_agent).exec("CVE-2025-0725")

    result = await llm_cache_retrieve(feature)
    cvssdiffexplain = cve.data_models.CVSSDiffExplainerModel.model_validate_json(result)
    assert isinstance(cvssdiffexplain, cve.data_models.CVSSDiffExplainerModel)
    assert (
        cvssdiffexplain.redhat_cvss3_vector
        == "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    )


async def test_component_intelligence_test_model():
    def feature():
        return component.ComponentIntelligence(rh_feature_agent).exec("curl")

    result = await llm_cache_retrieve(feature)
    componentintelligence = (
        component.data_models.ComponentIntelligenceModel.model_validate_json(result)
    )
    assert isinstance(
        componentintelligence, component.data_models.ComponentIntelligenceModel
    )
    assert componentintelligence.popularity_score == 1
    assert componentintelligence.confidence == 0.95


async def test_suggest_impact_with_bad_cve_test_model():
    def feature():
        return cve.SuggestImpact(rh_feature_agent).exec("BAD-CVE-ID")

    with pytest.raises(ValidationError) as excinfo:
        await feature()

    assert "String should match pattern" in str(excinfo)
