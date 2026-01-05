import asyncio
import logging

from typing import Awaitable

from aegis_ai import get_env_int
from google.genai.errors import ServerError
from pydantic_ai import Agent
from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior
from pydantic_ai.run import AgentRunResult

logger = logging.getLogger(__name__)

# Timeout in seconds for a single LLM prompt
llm_prompt_timeout = get_env_int("AEGIS_LLM_TIMEOUT_SECS", 300)

# Cap concurrent LLM calls across the process
llm_max_jobs = get_env_int("AEGIS_LLM_MAX_JOBS", 4)
llm_sem = asyncio.Semaphore(llm_max_jobs)

# The threshold for LLM input tokens to log a warning
llm_input_tokens_warn_thr = get_env_int("AEGIS_LLM_INPUT_TOKENS_WARN_THR", 65536)


# initial delay in seconds after getting HTTP 503 status code from LLM (doubled on each attempt)
PROMPT_RETRY_503_DELAY_INIT = 8

# temperature override while retrying a prompt
PROMPT_RETRY_TEMPERATURE = 0.9

# the period of time to monitor a running prompt
PROMPT_INFO_PERIOD = 60


async def run_with_heartbeat(runner: Awaitable, prefix: str) -> AgentRunResult:
    """await runner with llm_prompt_timeout and periodically log INFO messages
    with the given prefix each PROMPT_INFO_PERIOD seconds until runner finishes"""

    # Periodic warning logger while the run is in progress
    done_event = asyncio.Event()

    async def _warn_loop():
        loop = asyncio.get_running_loop()
        start_ts = loop.time()
        while not done_event.is_set():
            try:
                await asyncio.wait_for(done_event.wait(), timeout=PROMPT_INFO_PERIOD)
            except asyncio.TimeoutError:
                elapsed = int(loop.time() - start_ts)
                logger.info(f"{prefix}: still running after {elapsed}s")

    warn_task = asyncio.create_task(_warn_loop())
    try:
        return await asyncio.wait_for(runner, timeout=llm_prompt_timeout)
    finally:
        done_event.set()
        warn_task.cancel()
        try:
            await warn_task
        except asyncio.CancelledError:
            pass


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def _run(self, call_str, prompt, **kwargs):
        try:
            runner = self.agent.run(prompt.to_string(), **kwargs)
            return await run_with_heartbeat(runner, prefix=call_str)

        except asyncio.TimeoutError:
            # fmt: off
            msg = f"{call_str}: LLM request timed out after {llm_prompt_timeout} seconds"
            logger.warning(msg)
            raise RuntimeError(msg)
            # fmt: on

        except Exception as e:
            # log only exception name by default, details only when debugging
            logger.warning(f"{call_str} raised an exception: {e.__class__.__name__}")
            logger.debug(f"{call_str} raised an exception: {e}")
            raise

    async def run_if_safe(self, prompt, **kwargs):
        """
        Execute `self.agent.run(...)` only if the provided prompt passes `prompt.is_safe()`.
        Returns the model output on success, otherwise None.
        """
        # lazy import to avoid circular deps
        from aegis_ai.agents import agent_default_max_retries

        feat_name = self.__class__.__name__
        call_str = f"{feat_name}({prompt.context.cve_id})"
        logger.info(f"{call_str} = ?")
        async with llm_sem:
            if not await prompt.is_safe():
                msg = f"{call_str}: Safety agent blocked the prompt: unsafe content detected"
                logger.warning(msg)
                raise RuntimeError(msg)

            # will be merged with self.agent.model_settings by pydantic_ai
            model_settings = {}

            # how long we sleep before next attempt
            delay = 0

            # retry loop
            attempt = 0
            while True:
                msg = f"{call_str} retrying prompt"
                try:
                    result = await self._run(
                        call_str, prompt, model_settings=model_settings, **kwargs
                    )

                    # success (no exception)
                    break

                except (ModelHTTPError, ServerError) as e:
                    code = e.status_code if isinstance(e, ModelHTTPError) else e.code
                    if agent_default_max_retries <= attempt or code != 503:
                        # propagate other exceptions (or exceeded retry attempts)
                        raise

                    # retry the prompt with gradually increasing delay
                    delay = (delay * 2) if delay else PROMPT_RETRY_503_DELAY_INIT

                except UnexpectedModelBehavior as e:
                    if agent_default_max_retries <= attempt:
                        # exceeded retry attempts
                        raise

                    if "RECITATION" not in str(e):
                        # propagate other exceptions
                        raise

                    # retry with high temperature
                    # see https://github.com/RedHatProductSecurity/aegis-ai/issues/271
                    model_settings["temperature"] = PROMPT_RETRY_TEMPERATURE
                    msg += f" with temperature={PROMPT_RETRY_TEMPERATURE}"

                # increment the counter of retries
                attempt += 1

                # print a warning that we retry the prompt
                if delay:
                    msg += f" in {delay}s"
                msg += f", attempt {attempt}/{agent_default_max_retries}"
                logger.warning(msg)

                # wait before the next attempt
                await asyncio.sleep(delay)

        # check how many input tokens were processed by the LLM
        input_tokens = result._state.usage.input_tokens
        logger.debug(f"{call_str}: LLM processed {input_tokens} input tokens")

        # log a warning if the threshold is exceeded
        if llm_input_tokens_warn_thr < input_tokens:
            logger.warning(
                f"{call_str}: too many input tokens processed by LLM: {input_tokens}"
            )

        # log outcome of the feature call (if provided by the inherited class)
        outcome = result.output.printable_outcome()
        logger.info(f"{call_str} = {outcome}")

        return result
