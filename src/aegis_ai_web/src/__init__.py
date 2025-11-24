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
    from .data_models import FEEDBACK_SCHEMA

    # Read env var dynamically to support test fixtures that set it
    log_file = os.getenv(
        "AEGIS_WEB_FEEDBACK_LOG", f"{get_settings().config_dir}/feedback.csv"
    )
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Open in append mode with line buffering for immediate writes
    with open(log_path, "a", newline="", encoding="utf-8", buffering=1) as csvfile:
        # Acquire exclusive lock for thread- and process-safe writes
        fcntl.flock(csvfile.fileno(), fcntl.LOCK_EX)
        try:
            # Check file size after acquiring lock to avoid TOCTOU race condition
            # Use fstat on the file descriptor to get current size atomically
            file_size = os.fstat(csvfile.fileno()).st_size
            file_exists = file_size > 0

            writer = csv.DictWriter(csvfile, fieldnames=FEEDBACK_SCHEMA.field_names)

            # Write headers if this is a new file
            if not file_exists:
                writer.writeheader()

            # Write the feedback row
            writer.writerow(feedback_data)
        finally:
            # Release lock
            fcntl.flock(csvfile.fileno(), fcntl.LOCK_UN)
