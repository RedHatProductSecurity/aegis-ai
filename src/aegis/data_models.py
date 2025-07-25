# common data models/fields

import re
from typing import Annotated

import cvss
from pydantic import StringConstraints, AfterValidator, TypeAdapter


def is_cvss3_valid(cvss_str: str) -> bool:
    """return True if cvss_str is a valid CVSS3 vector"""
    try:
        # FIXME: cvss_str is *sometimes* prefixed with the actual score, which
        # breaks the validation.  Should we canonicalize the output from Aegis
        # instead?
        cvss_str = re.sub(r"^[0-9]+(\.[0-9])+/", "", cvss_str)

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
        pattern=r"^[0-9]+(\.[0-9])+/",
        strict=True,
        strip_whitespace=True,
    ),
    AfterValidator(validate_with_is_cvss3),
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
