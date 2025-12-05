# REST API
import os

from aegis_ai import truthy

AEGIS_REST_API_VERSION: str = "v1"
ENABLE_CONSOLE = os.getenv("AEGIS_WEB_ENABLE_CONSOLE", "false").lower() in truthy

web_feature_agent = os.getenv("AEGIS_WEB_FEATURE_AGENT", "public")
