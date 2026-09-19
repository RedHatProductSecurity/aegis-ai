from typing import Any


def filter_osv_response(data: dict[str, Any]) -> dict[str, Any]:
    """Return a focused subset of an OSV.dev vulnerability response.

    Strips bulky fields (e.g. ``affected[].versions``) that waste LLM
    context without providing analytical value.
    """
    if not data:
        return {}

    affected = []
    for entry in data.get("affected", []):
        filtered: dict[str, Any] = {}
        if "package" in entry:
            filtered["package"] = entry["package"]
        if "ranges" in entry:
            filtered["ranges"] = entry["ranges"]
        if "database_specific" in entry:
            filtered["database_specific"] = entry["database_specific"]
        if filtered:
            affected.append(filtered)

    return {
        "id": data.get("id", ""),
        "summary": data.get("summary", ""),
        "details": data.get("details", ""),
        "affected": affected,
        "database_specific": data.get("database_specific", {}),
    }
