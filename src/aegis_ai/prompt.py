from typing import Optional, Dict

from pydantic import BaseModel

from aegis_ai import get_settings, logger
from aegis_ai.agents import safety_agent

system_instruction = """
You are a Red Hat product security assistant.
Goals: be accurate, concise, and actionable.
Rules:
- Prefer facts over speculation; cite only provided context/tools.
- Use tools when needed; one tool call per step.
- Keep answers short and directly useful.
- Output must match the requested JSON schema when provided.
Safety: refuse harmful or unethical requests.
"""


class AegisPrompt(BaseModel):
    """
    A structured, composable representation of an LLM prompt.
    """

    # System instructions
    system_instruction: str = system_instruction

    # User instructions
    user_instruction: str
    goals: str
    rules: str

    # Contextual information should always come in as structured input
    context: BaseModel
    static_context: Optional[Dict] = None

    # Output data schema
    output_schema: Optional[Dict] = None

    async def is_safe(self):
        """Prompt safety check"""
        if not (get_settings().safety_enabled):
            logger.info("Safety agent check is disabled.")
            return True

        safety_result = await safety_agent.run(self.to_string())
        return "No" in safety_result.output

    def to_string(self, **kwargs) -> str:
        """
        Generate formatted prompt string.
        """

        prompt_parts = []

        prompt_parts.append(f"system: {self.system_instruction}\n")
        prompt_parts.append(f"user: {self.user_instruction}\n")

        if self.goals:
            prompt_parts.append(f"Goals:\n{self.goals}")

        if self.rules:
            prompt_parts.append(f"Behavior and Rules:\n{self.rules}")

        if self.context:
            prompt_parts.append(f"Context:\n{self.context}")

        if self.static_context:
            prompt_parts.append(f"Context:\n{self.static_context}")

        if self.output_schema:
            prompt_parts.append(
                f"Format: Should adhere to the following schema\n {self.output_schema}"
            )

        return "\n\n".join(prompt_parts)
