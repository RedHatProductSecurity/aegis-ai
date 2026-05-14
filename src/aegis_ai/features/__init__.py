import asyncio
import logging

from abc import ABC, abstractmethod
from typing import Any, Awaitable

from aegis_ai import get_env_int, get_settings
from google.genai.errors import ServerError
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior
from pydantic_ai.run import AgentRunResult

logger = logging.getLogger(__name__)

# Timeout in seconds for a single LLM prompt
llm_prompt_timeout = get_settings().default_llm_prompt_timeout

# Cap concurrent LLM calls across the process
llm_sem = asyncio.Semaphore(get_settings().llm_max_jobs)

# The threshold for LLM input tokens to log a warning
llm_input_tokens_warn_thr = get_env_int("AEGIS_LLM_INPUT_TOKENS_WARN_THR", 65536)


# initial delay in seconds after getting HTTP 503 status code from LLM (doubled on each attempt)
PROMPT_RETRY_503_DELAY_INIT = 8

# temperature override while retrying a prompt
PROMPT_RETRY_TEMPERATURE = 0.9

# the period of time to monitor a running prompt
PROMPT_INFO_PERIOD = 60

# Max times guarded_run re-invokes the LLM when _check_output returns a retry prompt (output enforcement).
_MAX_OUTPUT_ENFORCEMENT_RETRIES = 3


def id_from_context(context: BaseModel) -> str:
    """return entity ID for logging purposes based on context"""
    # Context may be CVE (cve_id) or component (component_name); use first non-None
    for attr in ("cve_id", "component_name"):
        context_id = getattr(context, attr, None)
        if context_id is not None:
            return context_id

    return f"{type(context).__name__}(...)"


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


class Feature(ABC):
    def __init__(self, agent: Agent):
        self.agent = agent

    @abstractmethod
    async def exec(self, *args: Any, **kwargs: Any) -> AgentRunResult:
        """Run the feature. Subclasses define their own parameter signatures."""
        ...

    def _check_output(self, result: AgentRunResult, deps: Any) -> str | None:
        """Validate the run result; return a retry prompt or None if acceptable.

        Override in subclasses to enforce feature-specific constraints.
        When a non-None string is returned, ``guarded_run`` will re-invoke
        the agent with the full conversation history plus this string as a
        new user turn, replicating the ModelRetry behaviour of output
        validators without requiring one on the shared agent.
        """
        return None

    async def _run(self, call_str, prompt, **kwargs):
        try:
            prompt_text = prompt.to_string() if hasattr(prompt, "to_string") else prompt
            runner = self.agent.run(prompt_text, **kwargs)
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

    async def guarded_run(self, prompt, **kwargs):
        """Execute the agent with safety, concurrency, retry, and timeout guards.

        Raises RuntimeError if the prompt fails the safety check or the
        agent cannot produce a result after retries.
        """
        # lazy import to avoid circular deps
        from aegis_ai.agents import agent_default_max_retries

        feat_name = self.__class__.__name__
        call_str = f"{feat_name}({id_from_context(prompt.context)})"
        logger.debug(f"{call_str} acquiring llm_sem lock")
        async with llm_sem:
            logger.info(f"{call_str} = ?")
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
                    if agent_default_max_retries <= attempt or code not in [500, 503]:
                        # propagate other exceptions (or exceeded retry attempts)
                        raise

                    # retry the prompt with gradually increasing delay
                    delay = (delay * 2) if delay else PROMPT_RETRY_503_DELAY_INIT

                except UnexpectedModelBehavior:
                    if agent_default_max_retries <= attempt:
                        # exceeded retry attempts
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

        # Output enforcement: let subclasses reject the result and ask
        # the LLM to retry with the full conversation context.  This
        # replaces the agent-level output_validator pattern which is
        # incompatible with per-run output_type in pydantic-ai >=1.66.
        for enforcement_attempt in range(_MAX_OUTPUT_ENFORCEMENT_RETRIES):
            retry_msg = self._check_output(result, kwargs.get("deps"))
            if retry_msg is None:
                break
            logger.warning(
                "%s: output enforcement retry %d/%d: %s",
                call_str,
                enforcement_attempt + 1,
                _MAX_OUTPUT_ENFORCEMENT_RETRIES,
                retry_msg,
            )
            retry_kwargs = {k: v for k, v in kwargs.items() if k != "message_history"}
            retry_kwargs["message_history"] = result.all_messages()
            result = await self._run(
                call_str,
                retry_msg,
                model_settings=model_settings,
                **retry_kwargs,
            )

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
