from aegis_ai import get_settings
from aegis_ai.osidb_bot.state import BotState, StateFileHandler
from aegis_ai.osidb_bot.util import FlawData, logger
from aegis_ai.data_models import CVEID

from pydantic_ai import Agent

import osidb_bindings
from osidb_bindings.session import Session

import requests

from datetime import datetime
from typing import Optional, Sequence


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


class FlawFinder:
    osidb: Session

    def __init__(self, osidb: Session) -> None:
        self.osidb = osidb

    def search(self, state: Optional[BotState] = None) -> Sequence[CVEID]:
        # TODO
        breakpoint()
        return []

    @staticmethod
    def validate(flaw_data: FlawData) -> None:
        # TODO
        return


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

        if not self.updated_fields:
            # nothing has changed
            raise RuntimeError("left unchanged")

    async def do(self) -> None:
        assert self.flaw_data

        # apply suggestions
        await self.apply_suggestions()

        # write flaw data
        try:
            flaw_uuid = self.flaw_data["uuid"]
            self.osidb.flaws.update(
                id=flaw_uuid,
                form_data=self.flaw_data,
            )
            logger.info(f"{self.cve}: updated {self.updated_fields}")

        except requests.exceptions.RequestException as e:
            self._warn("failed to save changes")

            if e.response is not None:
                logger.debug(f"{self.cve}: {e.response.text}")


class Bot:
    sfh: StateFileHandler
    agent: Agent
    osidb: Session
    total: int

    @staticmethod
    def _fail(msg):
        raise RuntimeError(f"[osidb-bot] {msg}")

    def __init__(self, state_file_handler: StateFileHandler, agent: Agent):
        self.sfh = state_file_handler
        self.agent = agent
        self.total = 0
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
            await flaw_updater.do()

        except RuntimeError as e:
            # something has failed
            logger.warning(f"{cve}: {str(e)}")

        finally:
            if not flaw_updater:
                # failed to read flaw data from OSIDB
                return

            # update state file
            state: BotState = flaw_updater.state()
            self.sfh.write_state(state)
            logger.info(f"{state}")

    async def process(self, cve_ids: Sequence[CVEID] = ()) -> None:
        if not cve_ids:
            # look for CVEs to process
            cve_ids = self.search_cve_ids()

        self.total = len(cve_ids)
        if not self.total:
            logger.info("nothing to do")
            return

        for i, cve in enumerate(cve_ids, start=1):
            logger.info(f"[{i}/{self.total}] processing {cve}")
            await self.process_cve(cve)
