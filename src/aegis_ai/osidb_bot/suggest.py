from aegis_ai.osidb_bot.util import FlawData, log_memory, logger
from aegis_ai.data_models import CVEID, cveid_validator
from aegis_ai.features import Feature, cve
from aegis_ai.features.data_models import AegisAnswer, AegisFeatureModel

from pydantic_ai import Agent

from datetime import datetime
from typing import Any, Optional


# define the quality of suggestions that we accept
METRICS_THR = {
    "data_quality": {
        "info_thr": 0.8,
        "skip_thr": 0.6,
    },
    "confidence": {
        "info_thr": 0.8,
        "skip_thr": 0.6,
    },
}


def check_metrics(
    feat_name: str, cve_id: str | CVEID, output: AegisFeatureModel
) -> Optional[str]:
    """Return None if metrics are acceptable, or the name of the failing metric.

    `cve_id` may be a `CVEID` or a raw string (including an empty string if the ID is missing)."""
    skip_reason: Optional[str] = None
    for field, thr_map in METRICS_THR.items():
        value = getattr(output, field)
        if value <= thr_map["info_thr"]:
            logger.info(f"{cve_id}: {feat_name}: too low {field}: {value}")
        if value <= thr_map["skip_thr"]:
            skip_reason = field

    if skip_reason:
        logger.warning(f"{cve_id}: {feat_name}: discarding suggestion")

    return skip_reason


async def exec_feature(feature: Feature, flaw_data: FlawData) -> Any:
    feat_name = feature.__class__.__name__
    cve_id_raw = flaw_data.get("cve_id", "?")
    try:
        cve_id: CVEID = cveid_validator.validate_python(cve_id_raw)
        log_memory(f"{feat_name}_start({cve_id})")
        result = await feature.exec(cve_id, static_context=flaw_data)
        log_memory(f"{feat_name}_end({cve_id})")
        output = result.output
        if isinstance(output, AegisFeatureModel):
            return output

    except Exception as e:
        msg = "exec_feature() terminated with Exception"
        logger.debug(f"{msg}: {str(e)}")
        raise RuntimeError(f"{msg}: {e.__class__.__name__}")


def update_field(
    flaw_data: FlawData,
    timestamp: datetime,
    dst: str,
    output: AegisAnswer,
    src: Optional[str] = None,
    value: Optional[str] = None,
    only_if_missing: bool = False,
) -> set[str]:
    assert (not src) or (not value)
    if only_if_missing and flaw_data.get(dst):
        # do not override existing field
        return set()

    cve_id = flaw_data.get("cve_id", "")
    skip_reason = check_metrics(dst, cve_id, output)
    if skip_reason:
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

    # record Aegis metadata
    aegis_meta = flaw_data.setdefault("aegis_meta", {})
    dst_field = aegis_meta.setdefault(dst, [])
    dst_field.append(
        {
            "type": "AI-Bot",
            "value": value,
            "explanation": output.explanation,
            "timestamp": timestamp.isoformat(),
            "data_quality": output.data_quality,
            "confidence": output.confidence,
        }
    )

    return set([dst])


async def suggest_components(
    agent: Agent, flaw_data: FlawData, ts: datetime
) -> set[str]:
    if flaw_data.get("components"):
        # the "components" field is already initialized, skip this!
        return set()

    # request the suggestion from Aegis
    feature = cve.SuggestAffectedComponents(agent)
    output = await exec_feature(feature, flaw_data)
    if output is None:
        return set()

    changed = update_field(flaw_data, ts, "components", output)

    # record suggested ecosystems in aegis_meta if any
    if output.ecosystems:
        update_field(flaw_data, ts, "_ecosystems", output, src="ecosystems")

    return changed


async def suggest_description(
    agent: Agent, flaw_data: FlawData, ts: datetime
) -> set[str]:
    # request the suggestion from Aegis
    feature = cve.SuggestDescriptionText(agent)
    output = await exec_feature(feature, flaw_data)
    if output is None:
        return set()

    # pick the relevant fields
    changed = update_field(flaw_data, ts, "title", output, src="suggested_title")
    changed |= update_field(
        flaw_data, ts, "cve_description", output, src="suggested_description"
    )

    return changed


async def suggest_cwe(agent: Agent, flaw_data: FlawData, ts: datetime) -> set[str]:
    if flaw_data["cwe_id"]:
        # do not override existing CWE ID
        return set()

    # only for logging
    cve_id = flaw_data.get("cve_id")

    # request the suggestion from Aegis
    feature = cve.SuggestCWE(agent)
    output = await exec_feature(feature, flaw_data)
    if output is None:
        return set()

    suggested_cwes = output.cwe
    if not suggested_cwes:
        logger.warning(f"{cve_id}: CWE suggestion failed")
        return set()

    # pick the first CWE in the list off suggested CWEs
    cwe = suggested_cwes[0]
    if 1 < len(suggested_cwes):
        logger.info(f"{cve_id}: picked {cwe}, ignoring {suggested_cwes[1:]}")

    return update_field(flaw_data, ts, "cwe_id", output, value=cwe)


async def suggest_impact(agent: Agent, flaw_data: FlawData, ts: datetime) -> set[str]:
    # look for existing RH CVSS
    for cvss in flaw_data["cvss_scores"]:
        if cvss["issuer"] == "RH":
            cve_id = flaw_data.get("cve_id")
            logger.warning(f"{cve_id}: refusing to overwrite RH CVSS")
            return set()

    # request the suggestion from Aegis
    feature = cve.SuggestImpact(agent)
    output = await exec_feature(feature, flaw_data)
    if output is None:
        return set()

    if not output.impact or not output.cvss3_vector:
        cve_id = flaw_data.get("cve_id")
        logger.warning(f"{cve_id}: impact suggestion incomplete, skipping")
        return set()

    # pick the "impact" field
    changed = update_field(flaw_data, ts, "impact", output)

    # record aegis_meta for RH CVSS (in the format used by OSIM)
    if not update_field(
        flaw_data, ts, "_cvss3_vector", output, value=output.cvss3_vector
    ):
        # do not update CVSS when check_metrics() decides to skip the update
        return changed

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
    suggest_components,
    suggest_description,
    suggest_cwe,
    suggest_impact,
]
