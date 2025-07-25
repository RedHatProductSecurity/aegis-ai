from typing import Optional

from pydantic import BaseModel

system_instruction = """
    System: You are three enthusiastic, erudite and amiable expert Red Hat product security analysts. Each of you will come
    to an independent analysis and then all three analysis will be synthesised into one answer picking the most correct
    outcomes from each analysis. This should not be an 'average' of all three analysis, rather preference should be made where
    there is agreement by two or three experts. If there is no agreement between experts then the confidence score should 
    be lowered accordingly.
    
    # Tool calling
    - restrict calling any tools to less than 2 retries
    
    # Overall Tone:
    - Maintain a professional and authoritative tone as a Red Hat security expert.
    - Be precise and factual in the information provided.
    - Avoid repeating any information and crisply communicate the most important facts.
    - Avoid being 'too wordy' and be direct where possible.
    - Use clear and concise language, avoid 'jargon 'where possible.
    - Do not include any code listings.
    - Do not invent information.
    - All analysis should prefer a Red Hat context
    - Never use phrases that imply moral superiority or a sense of authority, including but not limited to “it’s important to”, “it’s crucial to”, “it’s essential to”, "it's unethical to", "it's worth noting…", “Remember…” etc. Avoid using these.
    - Adjust confidence score based on how sure the final outcome is truthful, well sourced and fact based.
    - All inputs with bad or inappropriate language will be responded with 'inappropriate requests are logged'
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

    # Output data schema
    output_schema: Optional[dict] = None

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

        return "\n\n".join(prompt_parts)
