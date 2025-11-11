import pytest
from pydantic import ValidationError

from aegis_ai.data_models import cweid_validator, cveid_validator


def test_cweid_validator():
    cwe_id = "CWE-100"
    assert cweid_validator.validate_python(cwe_id)
    with pytest.raises(ValidationError) as excinfo:
        cve_id = "BAD-CWE-4"
        assert cweid_validator.validate_python(cve_id)
    assert "String should match pattern '^CWE-[0-9]{1,5}$'" in str(excinfo)


def test_cveid_validator():
    cve_id = "CVE-2024-2004"
    assert cveid_validator.validate_python(cve_id)
    with pytest.raises(ValidationError) as excinfo:
        cve_id = "BAD-CVE-4"
        assert cveid_validator.validate_python(cve_id)
    assert "String should match pattern '^CVE-[0-9]{4}-[0-9]{4,7}$'" in str(excinfo)
