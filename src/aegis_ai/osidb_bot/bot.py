from aegis_ai import get_settings
from aegis_ai.osidb_bot.state import BotState, StateFileHandler
from aegis_ai.osidb_bot.suggest import DEFAULT_SUGGESTION_LIST
from aegis_ai.osidb_bot.util import FlawData, logger
from aegis_ai.data_models import CVEID

from pydantic_ai import Agent

import osidb_bindings
from osidb_bindings.bindings.python_client.types import Unset
from osidb_bindings.session import Session

import asyncio
import requests
import textwrap

from datetime import datetime, timezone
from typing import Any, Optional, Sequence, cast


ELIGIBLE_FLAWS = {
    # only flaws coming from collectors
    "source": (
        # TODO: extend the sequence
        "CVEORG",
    ),
    # only flaws in the NEW state
    "classification": ({"workflow": "DEFAULT", "state": "NEW"},),
    # only flaws where Aegis has not been used yet
    "aegis_meta": ({},),
    # only flaws with no affects
    "affects": ([],),
    # only flaws with no owner
    "owner": ("",),
    # only flaws with empty description
    "cve_description": ("",),
    # only flaws with no statement
    "statement": ("",),
    # only flaws with no mitigation
    "mitigation": ("",),
}

FLAW_FIELDS = [
    "aegis_meta",
    "affects",
    "classification",
    "comment_zero",
    "comments",
    "components",
    "created_dt",
    "cve_description",
    "cve_id",
    "cvss_scores",
    "cwe_id",
    "embargoed",
    "impact",
    "mitigation",
    "owner",
    "references",
    "source",
    "statement",
    "title",
    "updated_dt",
    "uuid",
]


max_jobs_sem = asyncio.Semaphore(get_settings().llm_max_jobs)


def _kwargs_for_log(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of kwargs with datetime values as ISO date strings."""
    result: dict[str, Any] = {}
    for k, v in kwargs.items():
        if isinstance(v, datetime):
            result[k] = v.isoformat()
        else:
            result[k] = v
    return result


class FlawFinder:
    osidb: Session

    def __init__(self, osidb: Session) -> None:
        self.osidb = osidb

    def search(self, state: Optional[BotState] = None) -> Sequence[CVEID]:
        # infer search predicates from ELIGIBLE_FLAWS
        kwargs: dict[str, Any] = {
            "include_fields": ["cve_id"],
            "order": ["created_dt"],
            "source_in": [s for s in ELIGIBLE_FLAWS["source"]],
            "workflow_state_in": [
                cast(dict[str, str], c)["state"]
                for c in ELIGIBLE_FLAWS["classification"]
            ],
            # use a large page size to minimize round trips when only fetching IDs
            "limit": 1000,
        }

        # emptiness predicates for indexed fields
        for field, allowed in ELIGIBLE_FLAWS.items():
            if field in ("affects", "aegis_meta"):
                # not indexed in OSIDB
                continue

            if len(allowed) == 1 and not allowed[0]:
                key = f"{field}_isempty"
                kwargs[key] = True

        # filter by timestamp if state file is used
        if state is not None:
            kwargs["created_dt_gte"] = state.created_dt

        # initiate the OSIDB search
        logger.info("searching CVEs: %s", _kwargs_for_log(kwargs))
        flaw_iterator = self.osidb.flaws.retrieve_list_iterator(**kwargs)
        cve_ids = [flaw.cve_id for flaw in flaw_iterator]
        if state is None:
            return cve_ids

        # exclude the last processed CVE when resuming from state
        return [cve for cve in cve_ids if cve != state.last_cve]

    @staticmethod
    def validate(flaw_data: FlawData) -> None:
        for field, allowed in ELIGIBLE_FLAWS.items():
            value = flaw_data[field]
            if value in allowed:
                continue

            short_value = textwrap.shorten(str(value), width=64, placeholder=" [...]")
            msg = f'skipped because {field}="{short_value}", allowed={allowed}'
            raise RuntimeError(msg)


class FlawUpdater:
    osidb: Session
    agent: Agent
    cve: CVEID

    # OSIDB flaw from session.flaws.retrieve()
    flaw_data: Optional[FlawData]

    # list of fields updated by the agent
    updated_fields: set[str]

    def __init__(self, osidb: Session, agent: Agent, cve: CVEID):
        self.osidb = osidb
        self.agent = agent
        self.cve = cve
        self.updated_fields = set()

        try:
            # read flaw data
            flaw = self.osidb.flaws.retrieve(
                id=str(self.cve),
                include_fields=",".join(FLAW_FIELDS),
            )
            self.flaw_data = flaw.to_dict()
            assert self.flaw_data["cve_id"] == self.cve

        except requests.exceptions.RequestException:
            raise RuntimeError("unable to read flaw data from OSIDB")

    def _warn(self, msg: str) -> None:
        logger.warning(f"{self.cve}: {msg}")

    def state(self) -> BotState:
        assert self.flaw_data
        return BotState(
            last_cve=self.flaw_data["cve_id"],
            created_dt=datetime.fromisoformat(self.flaw_data["created_dt"]),
        )

    async def apply_suggestions(self) -> None:
        assert self.flaw_data

        # query current server time once (before requesting suggestions)
        timestamp: Optional[datetime] = None
        try:
            timestamp = self.osidb.status().dt
        except Exception:
            pass
        if timestamp is None or isinstance(timestamp, Unset):
            # use local time for timestamp if server time was not provided
            self._warn("failed to get OSIDB server time, using local time instead")
            timestamp = datetime.now(tz=timezone.utc)

        # requests suggestions sequentially one by one
        for fnc in DEFAULT_SUGGESTION_LIST:
            self.updated_fields |= await fnc(self.agent, self.flaw_data, timestamp)

        if not self.updated_fields:
            # nothing has changed
            raise RuntimeError("left unchanged")

    async def do(self) -> None:
        assert self.flaw_data

        # validate eligibility on the fresh flaw data to avoid TOCTOU
        FlawFinder.validate(self.flaw_data)

        # apply suggestions
        await self.apply_suggestions()

        # mark the flaw as processed by Aegis/osidb-bot
        aegis_meta = self.flaw_data.setdefault("aegis_meta", {})
        aegis_meta["processed"] = True

        # write flaw data
        flaw_saved: bool = False
        try:
            flaw_uuid = self.flaw_data["uuid"]
            self.osidb.flaws.update(
                id=flaw_uuid,
                form_data=self.flaw_data,
            )
            flaw_saved = True

            if "cvss_scores" in self.updated_fields:
                # Apply RH CVSS via subresource (flaws.update() does not update cvss_scores)
                rh_cvss = self.flaw_data["cvss_scores"][0]
                cast(Any, self.osidb.flaws).cvss_scores.create(
                    flaw_id=flaw_uuid,
                    form_data=rh_cvss,
                )

        except requests.exceptions.RequestException as e:
            if flaw_saved:
                self._warn("failed to save RH CVSS")
                self.updated_fields.remove("cvss_scores")
            else:
                self._warn(f"failed to save changes: {self.updated_fields}")
                self.updated_fields.clear()

            if e.response is not None:
                logger.debug(f"{self.cve}: {e.response.text}")

        if self.updated_fields:
            logger.info(f"{self.cve}: updated {self.updated_fields}")


class Bot:
    sfh: StateFileHandler
    agent: Agent
    osidb: Session
    total: int
    pending: dict[BotState, bool]

    @staticmethod
    def _fail(msg):
        raise RuntimeError(f"[osidb-bot] {msg}")

    def __init__(self, state_file_handler: StateFileHandler, agent: Agent):
        self.sfh = state_file_handler
        self.agent = agent
        self.total = 0
        self.pending = {}
        try:
            osidb_server = get_settings().osidb_server_url

            # TODO: drop this when https://issues.redhat.com/browse/AEGIS-354 is resolved
            if "osidb.prodsec.redhat.com" in osidb_server:
                Bot._fail(
                    f"this feature is experimental, refusing to connect {osidb_server}"
                )

            self.osidb = osidb_bindings.new_session(osidb_server_uri=osidb_server)

        except requests.exceptions.ConnectionError as e:
            Bot._fail(f"failed to establish OSIDB session: {e}")

    def search_cve_ids(self) -> Sequence[CVEID]:
        finder = FlawFinder(self.osidb)
        return finder.search(state=self.sfh.read_state())

    async def process_cve(self, cve: CVEID) -> None:
        flaw_updater: Optional[FlawUpdater] = None

        try:
            flaw_updater = FlawUpdater(self.osidb, self.agent, cve)
            self.pending[flaw_updater.state()] = True  # mark as pending
            await flaw_updater.do()

        except RuntimeError as e:
            # something has failed
            logger.warning(f"{cve}: {str(e)}")

        finally:
            if flaw_updater:
                self.pending[flaw_updater.state()] = False  # mark as done

            # determine the next state
            state: Optional[BotState] = None
            for s in sorted(self.pending.keys(), key=lambda s: s.created_dt):
                if self.pending[s]:
                    # this CVE is still being processed
                    break

                # record the last _done_ CVE
                state = s
                del self.pending[state]

            if not state:
                # the CVE with lowest created_dt is still being processed
                return

            # update state file
            self.sfh.write_state(state)

    async def process_cve_bounded(self, i: int, cve: CVEID) -> None:
        async with max_jobs_sem:
            logger.info(f"[{i}/{self.total}] processing {cve}")
            await self.process_cve(cve)

    async def process(self, cve_ids: Sequence[CVEID] = ()) -> None:
        if not cve_ids:
            # look for CVEs to process
            cve_ids = self.search_cve_ids()

        self.total = len(cve_ids)
        if not self.total:
            logger.info("nothing to do")
            return

        await asyncio.gather(
            *[self.process_cve_bounded(*job) for job in enumerate(cve_ids, start=1)]
        )
