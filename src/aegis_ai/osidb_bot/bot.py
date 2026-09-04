import asyncio
import textwrap
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast

import osidb_bindings
import requests
from osidb_bindings.bindings.python_client.types import Unset
from osidb_bindings.session import Session
from pydantic_ai import Agent

from aegis_ai import get_settings
from aegis_ai.data_models import CVEID
from aegis_ai.osidb_bot.state import BotPosition, BotStateFileHandler, StateProxy
from aegis_ai.osidb_bot.suggest import _KERNEL_FLAGS_KEY, DEFAULT_SUGGESTION_LIST
from aegis_ai.osidb_bot.util import FlawData, log_memory, logger


class FlawValidationError(RuntimeError):
    """Raised when a flaw fails eligibility validation."""


ELIGIBLE_FLAWS = {
    # only flaws coming from the following sources
    "source": (
        "APPLE",
        "CERT",
        "CUSTOMER",
        "CVE",
        "CVEORG",
        "DEBIAN",
        "DISTROS",
        "GENTOO",
        "GOOGLE",
        "HW_VENDOR",
        "INTERNET",
        "MAGEIA",
        "MOZILLA",
        "NVD",
        "OPENSSL",
        "OSSSECURITY",
        "OSV",
        "REDHAT",
        "RESEARCHER",
        "SECUNIA",
        "SUSE",
        "UBUNTU",
        "UPSTREAM",
    ),
    # only flaws with the DEFAULT workflow in the NEW state
    "classification": ({"workflow": "DEFAULT", "state": "NEW"},),
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

    def search(
        self,
        state: BotPosition,
        age_cutoff: datetime | None = None,
    ) -> Sequence[CVEID]:
        # infer search predicates from ELIGIBLE_FLAWS
        kwargs: dict[str, Any] = {
            "include_fields": ["cve_id", "updated_dt"],
            "cve_id__isempty": False,  # only flaws with a CVE ID
            "order": ["updated_dt"],
            "source_in": [s for s in ELIGIBLE_FLAWS["source"]],
            **{
                f"workflow_{predicate}_in": list(
                    dict.fromkeys(
                        cast(dict[str, str], c)[key]
                        for c in ELIGIBLE_FLAWS["classification"]
                    )
                )
                for key, predicate in (("workflow", "name"), ("state", "state"))
            },
            # use a large page size to minimize round trips when only fetching IDs
            "limit": 1000,
        }

        # emptiness predicates for indexed fields
        for field, allowed in ELIGIBLE_FLAWS.items():
            if field in ("affects",):
                # not indexed in OSIDB
                continue

            if len(allowed) == 1 and not allowed[0]:
                key = f"{field}_isempty"
                kwargs[key] = True

        # --max-age limits how far back we look by flaw creation time
        if age_cutoff is not None:
            kwargs["created_dt_gte"] = age_cutoff

        # state file position limits by flaw update time
        if state.updated_dt is not None:
            kwargs["updated_dt_gte"] = state.updated_dt

        # initiate the OSIDB search
        logger.info("searching CVEs: %s", _kwargs_for_log(kwargs))
        flaw_iterator = self.osidb.flaws.retrieve_list_iterator(**kwargs)

        if state.last_cve is None:
            return [flaw.cve_id for flaw in flaw_iterator]

        # skip the last processed CVE unless it was updated since last processing
        return [
            flaw.cve_id
            for flaw in flaw_iterator
            if flaw.cve_id != state.last_cve or flaw.updated_dt != state.updated_dt
        ]

    @staticmethod
    def validate(flaw_data: FlawData) -> None:
        for field, allowed in ELIGIBLE_FLAWS.items():
            value = flaw_data[field]
            if value in allowed:
                continue

            short_value = textwrap.shorten(str(value), width=64, placeholder=" [...]")
            msg = f'skipped because {field}="{short_value}", allowed={allowed}'
            raise FlawValidationError(msg)


class FlawUpdater:
    osidb: Session
    agent: Agent
    cve: CVEID
    force: bool
    read_only: bool
    retry_list: dict[str, int]
    on_failure: Any

    # OSIDB flaw from session.flaws.retrieve()
    flaw_data: FlawData | None

    # list of fields updated by the agent
    updated_fields: set[str]

    def __init__(
        self,
        osidb: Session,
        agent: Agent,
        cve: CVEID,
        *,
        force: bool = False,
        read_only: bool = False,
        retry_list: dict[str, int] | None = None,
        on_failure: Any = None,
    ):
        self.osidb = osidb
        self.agent = agent
        self.cve = cve
        self.force = force
        self.read_only = read_only
        self.retry_list = retry_list or {}
        self.on_failure = on_failure
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

    def _info(self, msg: str) -> None:
        logger.info(f"{self.cve}: {msg}")

    def _warn(self, msg: str) -> None:
        logger.warning(f"{self.cve}: {msg}")

    def _log_osidb_response(self, e: Exception) -> None:
        if isinstance(e, requests.exceptions.RequestException):
            response = getattr(e, "response", None)
            if response is not None:
                fl = response.text.partition("\n")[0]
                truncated = textwrap.shorten(fl, width=256, placeholder=" [...]")
                self._info(f"OSIDB response: {truncated}")

    def position(self) -> BotPosition:
        assert self.flaw_data
        return BotPosition(
            last_cve=self.flaw_data["cve_id"],
            updated_dt=datetime.fromisoformat(self.flaw_data["updated_dt"]),
        )

    async def apply_suggestions(self) -> bool:
        assert self.flaw_data
        all_ok: bool = True

        # query current server time once (before requesting suggestions)
        timestamp: datetime | None = None
        try:
            timestamp = self.osidb.status().dt
        except Exception:  # noqa: S110
            pass
        if timestamp is None or isinstance(timestamp, Unset):
            # use local time for timestamp if server time was not provided
            self._warn("failed to get OSIDB server time, using local time instead")
            timestamp = datetime.now(tz=UTC)

        # requests suggestions sequentially one by one
        for fnc in DEFAULT_SUGGESTION_LIST:
            try:
                self.updated_fields |= await fnc(self.agent, self.flaw_data, timestamp)
            except RuntimeError as e:
                all_ok = False
                self._warn(str(e))

        if not self.updated_fields:
            # nothing has changed (unexpectedly)
            self._warn("left unchanged")
            return False

        if not all_ok:
            # something has already failed
            return False

        aegis_meta = self.flaw_data.get("aegis_meta", {})
        if not isinstance(aegis_meta, dict):
            self._warn("unexpected type of aegis_meta")
            return False

        # if everything is OK, check that no suggestion was discarded with this timestamp
        return not any(
            entry.get("type", "") == "AI-Bot-Skipped"
            and entry.get("timestamp", None) == timestamp.isoformat()
            for sublist in aegis_meta.values()
            if isinstance(sublist, list)  # skip over ["processed"], which is bool
            for entry in sublist
            if isinstance(entry, dict)  # guard against malformed OSIDB data
        )

    def create_label(self, label_name: str, label_type: str = "alias") -> bool:
        """Create a flaw label with the given name and type, return True on success."""
        assert self.flaw_data
        if self.read_only:
            msg = f"read-only mode, skipping creation of label '{label_name}'"
            self._warn(msg)
            return False

        try:
            flaw_uuid = self.flaw_data["uuid"]
            cast(Any, self.osidb.flaws).labels.create(
                flaw_id=flaw_uuid,
                form_data={
                    "name": label_name,
                    "type": label_type,
                    "state": "NEW",
                },
            )
            self._info(f"created label '{label_name}'")
            return True

        except Exception as e:
            msg = f"failed to create label '{label_name}' ({e.__class__.__name__})"
            self._warn(msg)
            self._log_osidb_response(e)
            logger.debug("%s: %s", self.cve, e)
            return False

    def _create_labels(self) -> None:
        assert self.flaw_data
        entries = self.flaw_data.get("aegis_meta", {}).get(_KERNEL_FLAGS_KEY, [])
        labels: list[str] = []
        for entry in entries:
            if isinstance(entry, dict):
                val = entry.get("value", [])
                if isinstance(val, list):
                    labels.extend(val)
        labels = list(dict.fromkeys(labels))

        any_update = False
        for label_name in labels:
            if self.create_label(label_name):
                any_update = True

        if not any_update:
            self.updated_fields.discard(_KERNEL_FLAGS_KEY)

    def save_flaw(self) -> bool:
        """Save flaw data to OSIDB (two-step: flaw update + CVSS subresource).

        Returns True if the flaw was fully saved, False on error.
        """
        assert self.flaw_data
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

            # successfully processed (we do not retry when only label creation fails)
            self.retry_list.pop(self.cve, None)
            return True

        except Exception as e:
            # failed to save changes
            msg_suffix = f"({e.__class__.__name__})"
            if flaw_saved:
                self._warn(f"failed to save RH CVSS {msg_suffix}")
                self.updated_fields.remove("cvss_scores")
            else:
                self._warn(
                    f"failed to save changes: {self.updated_fields} {msg_suffix}"
                )
                self.updated_fields.clear()

            self._log_osidb_response(e)

            # log full exception in debug mode only
            logger.debug(f"{self.cve}: {e!s}")
            return False

    async def do(self) -> bool:
        assert self.flaw_data

        # validate eligibility on the fresh flaw data to avoid TOCTOU
        try:
            FlawFinder.validate(self.flaw_data)
        except RuntimeError as e:
            if self.force:
                self._warn(f"bypassing flaw eligibility check: {e!s}")
            else:
                # proactively remove ineligible CVEs from retry_list
                self.retry_list.pop(self.cve, None)
                raise

        # apply suggestions
        all_ok: bool = await self.apply_suggestions()

        # save flaw data only when any field has been updated
        processed: bool = False
        if self.updated_fields:
            if self.read_only:
                msg = f"read-only mode, skipping OSIDB update of {self.updated_fields}"
                self._warn(msg)
                return False

            # mark the flaw as processed by Aegis/osidb-bot
            aegis_meta = self.flaw_data.setdefault("aegis_meta", {})
            aegis_meta["processed"] = True

            # write flaw data
            processed = self.save_flaw()
            if not processed:
                all_ok = self.on_failure(self.cve) if self.on_failure else False

            if _KERNEL_FLAGS_KEY in self.updated_fields:
                self._create_labels()

        if self.updated_fields:
            self._info(f"updated {self.updated_fields}")

        if not all_ok:
            self.create_label("manual-triage", label_type="workflow")

        return processed


class Bot(StateProxy):
    agent: Agent
    osidb: Session
    pending: dict[BotPosition, bool]
    force: bool
    age_cutoff: datetime | None
    max_retries: int
    retrying_failed: bool

    def __init__(
        self,
        state_file_handler: BotStateFileHandler,
        agent: Agent,
        *,
        force: bool = False,
        read_only: bool = False,
        age_cutoff: datetime | None = None,
        max_retries: int = 0,
    ):
        super().__init__(state_file_handler, read_only=read_only)
        self.agent = agent
        self.force = force
        self.age_cutoff = age_cutoff
        self.max_retries = max_retries
        self.retrying_failed = False
        self.pending = {}
        try:
            osidb_server = get_settings().osidb_server_url
            self.osidb = osidb_bindings.new_session(osidb_server_uri=osidb_server)

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        ) as e:
            raise RuntimeError(f"failed to establish OSIDB session: {e}")

    def search_cve_ids(self) -> Sequence[CVEID]:
        finder = FlawFinder(self.osidb)
        return finder.search(
            state=self.state,
            age_cutoff=self.age_cutoff,
        )

    def schedule_retry(self, cve: CVEID) -> bool:
        if self.retrying_failed:
            # already retrying -> create the manual-triage label on the last retry
            remains = self.retry_list.get(cve)
            return remains is not None and remains > 1

        if not self.max_retries:
            # not retrying and retry is disabled
            return False

        # not yet retrying but retry is enabled -> schedule retry
        self.retry_list[cve] = self.max_retries
        return True

    async def process_cve(self, cve: CVEID) -> bool:
        flaw_updater: FlawUpdater | None = None

        try:
            flaw_updater = FlawUpdater(
                self.osidb,
                self.agent,
                cve,
                force=self.force,
                read_only=self.read_only,
                retry_list=self.retry_list,
                on_failure=self.schedule_retry,
            )

            if not self.retrying_failed:
                # mark as pending
                self.pending[flaw_updater.position()] = True

            return await flaw_updater.do()

        except BaseException as e:
            # something has failed
            handled_failure = isinstance(e, RuntimeError)
            if handled_failure:
                logger.warning(f"{cve}: {e!s}")

            # schedule retry if enabled (but not for validation failures)
            if (
                not isinstance(e, FlawValidationError)
                and not self.schedule_retry(cve)
                and flaw_updater
            ):
                # the last retry attempt failed, create the manual-triage label
                flaw_updater.create_label("manual-triage", label_type="workflow")

            if not handled_failure:
                # propagate all but RuntimeError exceptions
                raise

            return False

        finally:
            if self.retrying_failed:
                self.decrement_retry(cve)
            elif flaw_updater:
                # mark as done
                self.pending[flaw_updater.position()] = False

            # determine the next state
            pkeys = self.pending.keys()
            next_state: BotPosition | None = None
            for s in sorted(pkeys, key=lambda s: s.updated_dt or datetime.min):  # noqa: DTZ901
                if self.pending[s]:
                    # this CVE is still being processed
                    break

                # record the last _done_ CVE
                next_state = s
                del self.pending[next_state]

            # do not update state if the CVE with lowest updated_dt is still being processed
            if next_state:
                # update state (and state file unless read-only)
                assert not self.retrying_failed
                self.state = next_state

    async def _process_cve_list(self, cve_ids: Sequence[CVEID] = ()) -> None:
        total: int = len(cve_ids)
        processed: int = 0

        async def process_cve_bounded(i: int, cve: CVEID) -> None:
            nonlocal processed

            async with max_jobs_sem:
                logger.info(f"[{i}/{total}] processing {cve}")
                log_memory(f"cve_start({cve})")
                try:
                    if await self.process_cve(cve):
                        processed += 1
                except Exception as e:
                    msg = f"{cve}: unhandled exception: {e.__class__.__name__}"
                    logger.warning(msg)
                    logger.debug("%s: %s", cve, e)
                log_memory(f"cve_end({cve})")

        log_memory(f"batch_start({total} CVEs)")
        await asyncio.gather(
            *[process_cve_bounded(*job) for job in enumerate(cve_ids, start=1)]
        )
        log_memory("batch_end")
        logger.info(f"processed {processed} out of {total} CVEs")

    async def process(self, cve_ids: Sequence[CVEID] = ()) -> None:
        if not cve_ids:
            # look for CVEs to process
            cve_ids = self.search_cve_ids()

        await self._process_cve_list(cve_ids)

        if self.retry_list:
            logger.info("retrying failed CVEs")
            self.retrying_failed = True

            # sort the list such that CVEs with fewer remaining retry attempts are processed first
            retry_cves = sorted(self.retry_list, key=self.retry_list.__getitem__)
            await self._process_cve_list(retry_cves)
