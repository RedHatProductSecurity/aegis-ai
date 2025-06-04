from pydantic_ai import Agent

from jinja2 import (
    Environment,
    PackageLoader,
)

env_fs = Environment(loader=PackageLoader("aegis.features", "."))


class Feature:
    def __init__(self, agent: Agent):
        self.agent = agent
