import logging
from pydantic_ai import Agent


logger = logging.getLogger(__name__)


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent

    async def run_if_safe(self, prompt, **kwargs):
        """
        Execute `self.agent.run(...)` only if the provided prompt passes `prompt.is_safe()`.
        Returns the model output on success, otherwise None.
        """
        if await prompt.is_safe():
            return await self.agent.run(prompt.to_string(), **kwargs)

        logger.info("Safety agent identified issue with query.")
        return None
