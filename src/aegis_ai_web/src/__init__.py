# REST API
import os

from aegis_ai import get_env_flag

AEGIS_REST_API_VERSION: str = "v1"
ENABLE_CONSOLE = get_env_flag("AEGIS_WEB_ENABLE_CONSOLE", False)

web_feature_agent = os.getenv("AEGIS_WEB_FEATURE_AGENT", "public")
