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
        if await prompt.is_safe():
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
                logger.warning(
                    f"{self.__class__.__name__}: LLM request timed out after {llm_prompt_timeout} seconds"
                )
                return None

        logger.info("Safety agent identified issue with query.")
        return None
