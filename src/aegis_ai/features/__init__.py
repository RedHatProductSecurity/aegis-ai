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


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def run_if_safe(self, prompt, **kwargs):
        """
        Execute `self.agent.run(...)` only if the provided prompt passes `prompt.is_safe()`.
        Returns the model output on success, otherwise None.
        """
        if not await prompt.is_safe():
            msg = f"{self.__class__.__name__}: Safety agent blocked the prompt: unsafe content detected"
            logger.info(msg)
            raise RuntimeError(msg)

        try:
            async with llm_sem:
                return await asyncio.wait_for(
                    self.agent.run(
                        prompt.to_string(),
                        **kwargs,
                    ),
                    timeout=llm_prompt_timeout,
                )
        except asyncio.TimeoutError:
            msg = f"{self.__class__.__name__}: LLM request timed out after {llm_prompt_timeout} seconds"
            logger.warning(msg)
            raise RuntimeError(msg)
