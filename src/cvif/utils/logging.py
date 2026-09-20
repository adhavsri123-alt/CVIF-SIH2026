"""Structured and secure application logging for CVIF."""

import logging
from pathlib import Path
import re
import sys
from typing import Optional, Union

# Regex patterns for masking sensitive material in logs
SENSITIVE_PATTERNS = [
    (re.compile(r"(secret|private_key|key_hex|password|token)[\"']?\s*[:=]\s*[\"']?([0-9a-fA-F]{16,})", re.IGNORECASE), r"\1=***REDACTED***"),
]


class SecurityRedactionFilter(logging.Filter):
    """Filter that masks potential cryptographic keys, secrets, or sensitive hashes in log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, repl in SENSITIVE_PATTERNS:
                record.msg = pattern.sub(repl, record.msg)
        return True


def setup_logger(
    name: str = "cvif",
    level: str = "INFO",
    log_file: Optional[Union[str, Path]] = None,
) -> logging.Logger:
    """Configure a thread-safe, sanitized logger for CVIF components."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers on re-configuration
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SecurityRedactionFilter())
        logger.addHandler(console_handler)

        # File handler if requested
        if log_file:
            path = Path(log_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.addFilter(SecurityRedactionFilter())
            logger.addHandler(file_handler)

    return logger
