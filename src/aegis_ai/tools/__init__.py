import logging
from datetime import date
from typing import Optional

from pydantic import BaseModel
from pydantic_ai import RunContext, Tool

logger = logging.getLogger(__name__)


class BaseToolOutput(BaseModel):
    status: str = "success"
    error_message: Optional[str] = None


@Tool
async def date_tool(ctx: RunContext) -> str:
    """Returns the current date."""
    logger.info("calling date_lookup")
    today = date.today()
    return str(today)
