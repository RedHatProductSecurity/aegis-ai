import asyncio
import logging
import os

from pydantic_ai import Agent

logger = logging.getLogger(__name__)

# Timeout in seconds for a single LLM prompt
llm_prompt_timeout = int(os.getenv("AEGIS_LLM_TIMEOUT_SECS", "300"))

# Cap concurrent LLM calls across the process
llm_max_jobs = int(os.getenv("AEGIS_LLM_MAX_JOBS", "4"))
llm_sem = asyncio.Semaphore(llm_max_jobs)

# The threshold for LLM input tokens to log a warning
llm_input_tokens_warn_thr = int(os.getenv("AEGIS_LLM_INPUT_TOKENS_WARN_THR", 16384))


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def _run(self, call_str, prompt, **kwargs):
        try:
            runner = self.agent.run(prompt.to_string(), **kwargs)
            return await asyncio.wait_for(runner, timeout=llm_prompt_timeout)

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
        feat_name = self.__class__.__name__
        call_str = f"{feat_name}({prompt.context.cve_id})"
        logger.info(f"{call_str} = ?")
        async with llm_sem:
            if not await prompt.is_safe():
                msg = f"{call_str}: Safety agent blocked the prompt: unsafe content detected"
                logger.warning(msg)
                raise RuntimeError(msg)

            result = await self._run(call_str, prompt, **kwargs)

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
