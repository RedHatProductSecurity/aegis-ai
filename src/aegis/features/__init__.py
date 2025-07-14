from pydantic_ai import Agent


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent
