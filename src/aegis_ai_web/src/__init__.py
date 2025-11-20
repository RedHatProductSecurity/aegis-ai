# REST API
import csv
import fcntl
import os
from pathlib import Path

from aegis_ai import truthy, get_settings

AEGIS_REST_API_VERSION: str = "v1"

feature_agent = os.getenv("AEGIS_WEB_FEATURE_AGENT", "public")
feedback_log = os.getenv(
    "AEGIS_WEB_FEEDBACK_LOG", f"{get_settings().config_dir}/feedback.csv"
)

ENABLE_CONSOLE = os.getenv("AEGIS_WEB_ENABLE_CONSOLE", "false").lower() in truthy


def write_feedback_to_csv(feedback_data: dict) -> None:
    """
    Write feedback data to CSV file.

    Automatically handles CSV escaping and creates headers if file doesn't exist.
    Uses file locking to ensure thread- and process-safe writes.
    """
    from .models import FEEDBACK_SCHEMA

    log_path = Path(feedback_log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if file exists to determine if we need to write headers
    file_exists = log_path.exists() and log_path.stat().st_size > 0

    # Open in append mode with line buffering for immediate writes
    with open(log_path, "a", newline="", encoding="utf-8", buffering=1) as csvfile:
        # Acquire exclusive lock for thread- and process-safe writes
        fcntl.flock(csvfile.fileno(), fcntl.LOCK_EX)
        try:
            writer = csv.DictWriter(csvfile, fieldnames=FEEDBACK_SCHEMA.field_names)

            # Write headers if this is a new file
            if not file_exists:
                writer.writeheader()

            # Write the feedback row
            writer.writerow(feedback_data)
        finally:
            # Release lock
            fcntl.flock(csvfile.fileno(), fcntl.LOCK_UN)
