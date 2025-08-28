# common data models/fields

from typing import Annotated

import cvss
from pydantic import StringConstraints, TypeAdapter, BeforeValidator, BaseModel, Field


def is_cvss_valid(cvss_str: str, cvss_fw: str = "CVSS3") -> bool:
    """Return True if cvss_str is a valid vector for the given CVSS framework."""
    try:
        cvss_constructor = getattr(cvss, cvss_fw)
        cvss_constructor(cvss_str)
        return True

    except cvss.CVSSError:
        return False


def _make_cvss_validator(cvss_fw: str):
    """Factory returning a pydantic validator for CVSS strings."""

    def _validator(v: str) -> str:
        if not is_cvss_valid(v, cvss_fw):
            raise ValueError(f"'{v}' is not a valid {cvss_fw} vector.")
        return v

    return _validator


def _make_cvss_model(cvss_fw: str):
    """Factory returning a pydantic model for CVSS strings."""
    return Annotated[
        str,
        StringConstraints(
            strict=True,
            strip_whitespace=True,
        ),
        BeforeValidator(_make_cvss_validator(cvss_fw)),
    ]


# cvss3 field
CVSS3Vector = _make_cvss_model("CVSS3")

# cvss4_field
CVSS4Vector = _make_cvss_model("CVSS4")

# cve id field
CVEID = Annotated[
    str,
    StringConstraints(
        pattern=r"^CVE-[0-9]{4}-[0-9]{4,7}$",
        strict=True,
        strip_whitespace=True,
    ),
]
# create dynamic CVEID validator
cveid_validator = TypeAdapter(CVEID)

# cwe id field
CWEID = Annotated[
    str,
    StringConstraints(
        pattern=r"^CWE-\d+$",
        strict=True,
        strip_whitespace=True,
    ),
]
# create dynamic CWEID validator
cweid_validator = TypeAdapter(CWEID)


class SafetyReport(BaseModel):
    is_safe: bool = Field(description="True if the prompt is safe, False otherwise.")
    reason: str | None = Field(
        None, description="The reason for the classification, if unsafe."
    )
