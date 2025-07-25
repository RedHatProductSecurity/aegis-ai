"""
Aegis chat: example app showing web chat.

"""

from __future__ import annotations as _annotations

from pathlib import Path

import json
import logging
from datetime import datetime, timezone
from typing import Annotated, List, Literal, Optional

import fastapi
from fastapi import Form
from fastapi.responses import FileResponse, StreamingResponse
from typing_extensions import TypedDict

from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic import BaseModel

from aegis_ai.agents import public_feature_agent

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class AgentOutputModel(BaseModel):
    text: str = ""  # Default for simple streaming


THIS_DIR = Path(__file__).parent

app = fastapi.FastAPI()


@app.get("/")
async def index() -> FileResponse:
    return FileResponse((THIS_DIR / "chat_app.html"), media_type="text/html")


@app.get("/chat_app.js")
async def main_js() -> FileResponse:
    return FileResponse((THIS_DIR / "chat_app.js"), media_type="text/javascript")


@app.get("/logo.png")
async def logo_png() -> FileResponse:
    return FileResponse((THIS_DIR / "logo.png"), media_type="image/png")


class ChatMessage(TypedDict):
    role: Literal["user", "model"]
    timestamp: str
    content: str


def to_chat_message(m: ModelMessage) -> ChatMessage:
    first_part = m.parts[0]
    if isinstance(m, ModelRequest):
        if isinstance(first_part, UserPromptPart):
            assert isinstance(first_part.content, str)
            return {
                "role": "user",
                "timestamp": first_part.timestamp.isoformat(),
                "content": first_part.content,
            }
    elif isinstance(m, ModelResponse):
        if isinstance(first_part, TextPart):
            # Use the timestamp from the ModelResponse itself if available,
            # or from the first part. ModelResponse has a timestamp field.
            return {
                "role": "model",
                "timestamp": m.timestamp.isoformat(),  # ModelResponse has timestamp
                "content": first_part.content,
            }
    raise UnexpectedModelBehavior(f"Unexpected message type for chat app: {m}")


@app.post("/chat/")
async def post_chat(
    prompt: Annotated[str, Form()],
    history_json: Annotated[Optional[str], Form()] = None,
) -> StreamingResponse:
    async def stream_messages():
        user_chat_message = {
            "system_prompt": "You are a helpful assistant with access to several tools. You should use these tools to answer questions that require external information.**Prioritize using tools before trying to answer directly.**",
            "role": "user",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "content": prompt,
        }
        yield json.dumps(user_chat_message).encode("utf-8") + b"\n"

        message_history: List[ModelMessage] = []
        if history_json:
            try:
                client_history: List[ChatMessage] = json.loads(history_json)
                for msg in client_history:
                    if msg["role"] == "user":
                        # PASS TIMESTAMP TO UserPromptPart
                        message_history.append(
                            ModelRequest(parts=[UserPromptPart(content=msg["content"])])
                        )
                    elif msg["role"] == "model":
                        # PASS TIMESTAMP TO TextPart
                        message_history.append(
                            ModelResponse(parts=[TextPart(content=msg["content"])])
                        )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.error(
                    f"Failed to parse history_json from client: {e}. Received: {history_json[:200]}..."
                )
            except Exception as e:
                logger.error(f"Unexpected error parsing history_json: {e}")

        # TODO: .run_stream does not invoke tools use Agent.iter instead
        async with public_feature_agent.run_stream(
            prompt, message_history=message_history
        ) as result:
            ai_response_content = ""

            async for text_part_content in result.stream(debounce_by=0.01):
                m = ModelResponse(
                    parts=[TextPart(content=text_part_content)],
                    timestamp=datetime.now(tz=timezone.utc),
                )  # Use current time for display
                yield json.dumps(to_chat_message(m)).encode("utf-8") + b"\n"
                ai_response_content += text_part_content

    return StreamingResponse(stream_messages(), media_type="text/plain")
