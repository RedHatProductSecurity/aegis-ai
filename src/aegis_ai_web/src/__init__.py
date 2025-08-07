# REST API version
import os

AEGIS_REST_API_VERSION: str = "v1"

feature_agent = os.getenv("AEGIS_WEB_FEATURE_AGENT", "public")
