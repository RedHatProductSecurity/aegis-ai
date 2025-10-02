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

    async def _timeout_wrap(self, prompt, **kwargs):
        try:
            runner = self.agent.run(prompt.to_string(), **kwargs)
            return await asyncio.wait_for(runner, timeout=llm_prompt_timeout)

        except asyncio.TimeoutError:
            msg = f"{self.__class__.__name__}: LLM request timed out after {llm_prompt_timeout} seconds"
            logger.warning(msg)
            raise RuntimeError(msg)

    async def run_if_safe(self, prompt, **kwargs):
        """
        Execute `self.agent.run(...)` only if the provided prompt passes `prompt.is_safe()`.
        Returns the model output on success, otherwise None.
        """
        async with llm_sem:
            if not await prompt.is_safe():
                msg = f"{self.__class__.__name__}: Safety agent blocked the prompt: unsafe content detected"
                logger.info(msg)
                raise RuntimeError(msg)

            result = await self._timeout_wrap(prompt, **kwargs)

        # check how many input tokens were processed by the LLM
        input_tokens = result._state.usage.input_tokens
        logger.debug(
            f"{self.__class__.__name__}: LLM processed {input_tokens} input tokens"
        )

        # log a warning if the threshold is exceeded
        if llm_input_tokens_warn_thr < input_tokens:
            logger.warning(
                f"{self.__class__.__name__}: too many input tokens processed by LLM: {input_tokens}"
            )

        return result
