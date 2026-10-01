"""Shared record-time and version filtering for feedback and bot KPIs."""

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def timestamp_in_range(
    timestamp: str | None, after: datetime | None, before: datetime | None
) -> bool:
    if after is None and before is None:
        return True
    if not timestamp:
        return False
    try:
        value = utc(datetime.fromisoformat(timestamp))
    except ValueError:
        return False
    return (after is None or value >= utc(after)) and (
        before is None or value <= utc(before)
    )


@dataclass(frozen=True)
class KPIRecordFilters:
    """Inclusive record timestamps; empty version denotes unknown provenance."""

    recorded_after: datetime | None = None
    recorded_before: datetime | None = None
    aegis_versions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.recorded_after is not None
            and self.recorded_before is not None
            and utc(self.recorded_after) > utc(self.recorded_before)
        ):
            raise HTTPException(
                422, "recorded_after must be earlier than recorded_before."
            )

    def matches(self, timestamp: str | None, version: str) -> bool:
        return (
            not self.aegis_versions or version in self.aegis_versions
        ) and timestamp_in_range(timestamp, self.recorded_after, self.recorded_before)


NO_RECORD_FILTERS = KPIRecordFilters()
