"""
Feedback logger module for Aegis Web API.

Provides AegisLogger utility class with static methods for thread-safe CSV feedback logging.
"""

import csv
import fcntl
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from aegis_ai import __version__, get_settings
from aegis_ai_web.src.data_models import FEEDBACK_SCHEMA

logger = logging.getLogger(__name__)


class AegisLogger:
    """
    Singleton class for managing feedback log file operations.

    Encapsulates CSV reading and writing with thread-safe file locking.
    """

    @staticmethod
    def _get_log_path() -> Path:
        """
        Get the log file path from environment variable or default location.

        Reads env var dynamically to support test fixtures that set it.
        """
        log_file = os.getenv(
            "AEGIS_WEB_FEEDBACK_LOG", f"{get_settings().config_dir}/feedback.csv"
        )
        return Path(log_file)

    @staticmethod
    def write(feedback_data: dict) -> None:
        """
        Write feedback data to CSV file.

        Automatically handles CSV escaping and creates headers if file doesn't exist.
        Uses file locking to ensure thread- and process-safe writes.
        Automatically adds datetime and AEGIS version to the feedback data.

        Args:
            feedback_data: Dictionary containing feedback data to write
        """
        log_path = AegisLogger._get_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Add datetime and version fields if not already present
        row_data = feedback_data.copy()
        if "datetime" not in row_data:
            row_data["datetime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if "version" not in row_data:
            row_data["version"] = __version__

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
                writer.writerow(row_data)
            finally:
                # Release lock
                fcntl.flock(csvfile.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def read() -> List[Dict[str, str]]:
        """
        Read and parse feedback log entries from CSV file.

        Returns:
            List of Dict entries where all values are strings from CSV.
            Returns empty list if file doesn't exist or has no valid entries.
        """
        log_path = AegisLogger._get_log_path()
        entries = []

        # Open file unconditionally and handle FileNotFoundError to avoid TOCTOU race
        try:
            with open(log_path, "r", newline="", encoding="utf-8") as csvfile:
                # Acquire shared lock for thread-safe reads
                fcntl.flock(csvfile.fileno(), fcntl.LOCK_SH)
                try:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        # Validate entry matches schema
                        if FEEDBACK_SCHEMA.validate_parsed_log(row):
                            # Normalize accept field to lowercase
                            if "accept" in row and row["accept"]:
                                row["accept"] = row["accept"].lower()
                            entries.append(row)
                        else:
                            # Log warning for invalid entries that fail validation
                            cve_id = row.get("cve_id", "unknown")
                            logger.warning(
                                f"Invalid feedback log entry skipped: CVE ID {cve_id}",
                            )
                finally:
                    # Release lock
                    fcntl.flock(csvfile.fileno(), fcntl.LOCK_UN)
        except FileNotFoundError:
            # File doesn't exist, return empty list
            return []

        return entries
