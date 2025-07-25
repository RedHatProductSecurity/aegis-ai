# common data models/fields

from typing import Annotated

import cvss
from pydantic import StringConstraints, TypeAdapter, BeforeValidator


def is_cvss3_valid(cvss_str: str) -> bool:
    """return True if cvss_str is a valid CVSS3 vector"""
    try:
        cvss.cvss3.CVSS3(cvss_str)
        return True

    except cvss.CVSSError:
        return False


def validate_with_is_cvss3(v: str) -> str:
    if not is_cvss3_valid(v):
        raise ValueError(f"'{v}' is not a valid CVSS3 vector.")
    return v


# cvss3 field
CVSS3Vector = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=True,
    ),
    BeforeValidator(validate_with_is_cvss3),
]


def is_cvss4_valid(cvss_str: str) -> bool:
    """return True if cvss_str is a valid CVSS3 vector"""
    try:
        cvss.cvss4.CVSS4(cvss_str)
        return True

    except cvss.CVSSError:
        return False


def validate_with_is_cvss4(v: str) -> str:
    if not is_cvss4_valid(v):
        raise ValueError(f"'{v}' is not a valid CVSS3 vector.")
    return v


# cvss4 field
CVSS4Vector = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=True,
    ),
    BeforeValidator(validate_with_is_cvss4),
]

# cve id field
CVEID = Annotated[
    str,
    StringConstraints(
        pattern=r"^CVE-\d{4}-\d{4,7}$",
        strict=True,
        strip_whitespace=True,
    ),
]

# create dynamic CVEID validator
cveid_validator = TypeAdapter(CVEID)
