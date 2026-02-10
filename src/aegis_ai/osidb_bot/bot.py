from aegis_ai.osidb_bot.state import StateFileHandler
from aegis_ai.data_models import CVEID

from pydantic_ai import Agent

from typing import Sequence


class Bot:
    sfh: StateFileHandler
    agent: Agent

    def __init__(self, state_file_handler: StateFileHandler, agent: Agent):
        self.sfh = state_file_handler
        self.agent = agent

    async def process(self, cve_ids: Sequence[CVEID] = ()) -> None:
        breakpoint()
