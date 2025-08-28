import pytest
from pydantic import ValidationError

from aegis_ai.data_models import CWEID, cweid_validator, cveid_validator, CVEID


def test_cweid():
    cwe_id = CWEID("CWE-100")
    assert cweid_validator.validate_python(cwe_id)
    with pytest.raises(ValidationError) as excinfo:
        cve_id = CWEID("BAD-CWE-4")
        assert cweid_validator.validate_python(cve_id)
    assert "String should match pattern '^CWE-\\d+$'" in str(excinfo)


def test_cveid():
    cve_id = CVEID("CVE-2024-2004")
    assert cveid_validator.validate_python(cve_id)
    with pytest.raises(ValidationError) as excinfo:
        cve_id = CVEID("BAD-CVE-4")
        assert cveid_validator.validate_python(cve_id)
    assert "String should match pattern '^CVE-[0-9]{4}-[0-9]{4,7}$'" in str(excinfo)
