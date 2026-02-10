from aegis_ai.osidb_bot.util import FlawData, logger
from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features import Feature, cve

from pydantic_ai import Agent

from typing import Any, Optional


async def exec_feature(feature: Feature, flaw_data: FlawData) -> Any:
    try:
        cve_id: CVEID = cveid_validator.validate_python(flaw_data["cve_id"])
        result = await feature.exec(cve_id, static_context=flaw_data)
        return result.output
    except Exception as e:
        msg = "exec_feature() terminated with Exception"
        logger.debug(f"{msg}: {str(e)}")
        raise RuntimeError(f"{msg}: {e.__class__.__name__}")


def update_field(
    flaw_data: FlawData,
    dst: str,
    output: Any = None,
    src: Optional[str] = None,
    value: Optional[str] = None,
    only_if_missing: bool = False,
) -> set[str]:
    assert (not src) or (not value)
    if only_if_missing and flaw_data.get(dst):
        # do not override existing field
        return set()

    # get source value
    if value is None:
        if src is None:
            # unless overridden by the caller, assume 1:1 field mapping
            src = dst

        value = getattr(output, src)

    # check the original value in flaw_data
    orig_val = flaw_data.get(dst)
    if type(orig_val) is type(value) and orig_val == value:
        # skip the update if the field already has the same type and value
        return set()

    # write to destination
    flaw_data[dst] = value

    # TODO: update metadata

    return set([dst])


async def suggest_description(agent: Agent, flaw_data: FlawData) -> set[str]:
    # request the suggestion from Aegis
    feature = cve.SuggestDescriptionText(agent)
    output = await exec_feature(feature, flaw_data)

    # pick the relevant fields
    changed = update_field(flaw_data, "title", output, src="suggested_title")
    changed |= update_field(
        flaw_data, "cve_description", output, src="suggested_description"
    )

    # TODO: drop this when https://issues.redhat.com/browse/AEGIS-367 is resolved
    changed |= update_field(flaw_data, "components", output, only_if_missing=True)
    if not flaw_data.get("components"):
        # If the "components" field is still missing, we would not be able to
        # update the flaw in OSIDB later on.  Terminate the sugestions now with
        # a user-friendly warning message.
        raise RuntimeError("failed to determine components, giving up")

    return changed


async def suggest_cwe(agent: Agent, flaw_data: FlawData) -> set[str]:
    if flaw_data["cwe_id"]:
        # do not override existing CWE ID
        return set()

    # only for logging
    cve_id = flaw_data.get("cve_id")

    # request the suggestion from Aegis
    feature = cve.SuggestCWE(agent)
    output = await exec_feature(feature, flaw_data)
    suggested_cwes = output.cwe
    if not suggested_cwes:
        logger.warning(f"{cve_id}: CWE suggestion failed")
        return set()

    # pick the first CWE in the list off suggested CWEs
    cwe = suggested_cwes[0]
    if 1 < len(suggested_cwes):
        logger.info(f"{cve_id}: picked {cwe}, ignoring {suggested_cwes[1:]}")

    return update_field(flaw_data, "cwe_id", value=cwe)


async def suggest_impact(agent: Agent, flaw_data: FlawData) -> set[str]:
    # request the suggestion from Aegis
    feature = cve.SuggestImpact(agent)
    output = await exec_feature(feature, flaw_data)

    # look for existing RH CVSS
    for cvss in flaw_data["cvss_scores"]:
        if cvss["issuer"] == "RH":
            cve_id = flaw_data.get("cve_id")
            logger.warning(f"{cve_id}: refusing to overwrite RH CVSS")
            return set()

    # pick the "impact" field
    changed = update_field(flaw_data, "impact", output)

    # RH CVSS is a subresource in OSIDB (flaws.cvss_scores), not part of flaw update.
    # Store pending data for the bot to apply via osidb.flaws.cvss_scores create/update.
    rh_cvss = {
        "score": output.cvss3_score,
        "vector": output.cvss3_vector,
        "cvss_version": "V3",
        "issuer": "RH",
        "embargoed": flaw_data["embargoed"],
    }
    flaw_data["cvss_scores"] = [rh_cvss]
    changed.add("cvss_scores")
    return changed


DEFAULT_SUGGESTION_LIST = [
    suggest_description,
    suggest_cwe,
    suggest_impact,
]
