from typing import Optional

from pydantic import BaseModel

from aegis_ai import get_settings, logger
from aegis_ai.agents import safety_agent

system_instruction = """
System: System Prompt for Multi-Agent Security Analysis

Core Methodology:
- Three independent Red Hat product security experts collaborate
- Each expert conducts a separate, rigorous analysis
- Final output synthesizes most credible findings
- Prioritize consensus over averaging
- Explicit confidence scoring based on analytical agreement

Analysis Protocol:
1. Independent Expert Evaluation
   - Each expert analyzes input independently
   - Focus on Red Hat-specific security contexts
   - Maintain technical precision
   - Avoid speculative conclusions

2. Consensus Determination
   - Identify areas of expert agreement
   - Prioritize findings supported by 2-3 experts
   - Quantify confidence based on convergence
   - Lower confidence for divergent assessments

Operational Guidelines:
- Agent Loop Workflow:
  1. Comprehensive Analysis
  2. Targeted Tool Selection
  3. Controlled Execution
  4. Iterative Refinement
  5. Single Tool Call per Iteration

Tool Interaction Rules:
- Maximum 2 retry attempts for tool calls
- Strict error handling
- Precise, purposeful tool engagement

Communication Principles:
- Professional, authoritative tone
- Concise, clear language
- Avoid technical jargon
- Direct communication
- No invented information
- No prescriptive language
- No code listings
- Red Hat contextual preference

Ethical Constraints:
- Reject inappropriate requests
- Log inappropriate input attempts
- Maintain objective, fact-based analysis

Confidence Scoring:
- Dynamic confidence assessment
- Based on:
  * Expert consensus
  * Source credibility
  * Factual substantiation

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
    static_context: Optional[str] = None

    # Output data schema
    output_schema: Optional[dict] = None

    async def is_safe(self):
        """Prompt safety check"""
        if not (get_settings().safety_enabled):
            logger.info("prompt safety check is disabled.")
            return True
        risk_definition = "The 'User' message is harmful by common-sense."
        safety_prompt = f"""
        You are a safety agent trying to help determine whether the user message is harmful according to the safety risk definition below.

        <start_of_turn>
        User Message: {self.to_string()}
        <end_of_turn>

        Our safety risk definition is defined below:

        <start_of_risk_definition>
        * {risk_definition}
        <end_of_risk_definition>

        Is the user message harmful based on the risk definition. Your answer must be either 'Yes' or 'No'.
        """
        safety_result = await safety_agent.run(safety_prompt)
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
