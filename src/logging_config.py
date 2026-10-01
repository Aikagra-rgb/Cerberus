"""
Structured logging configuration for Cerberus.
Uses structlog with JSON output for production, pretty console for development.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import structlog


def configure_logging(level: str = "INFO", json_output: bool = None, log_file: str = None):
    """
    Configure structlog for the application with optional log rotation.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Force JSON output. Defaults to True if not in TTY or if LOG_JSON=1
        log_file: Optional path to log file with automatic 10MB rotation
    """
    if json_output is None:
        json_output = not sys.stdout.isatty() or os.getenv("LOG_JSON", "0") == "1"

    log_file_path = log_file or os.getenv("LOG_FILE", "").strip()
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file_path:
        log_dir = os.path.dirname(os.path.abspath(log_file_path))
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handlers.append(file_handler)

    # Standard library logging config
    logging.basicConfig(
        format="%(message)s",
        handlers=handlers,
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,
    )

    # Shared processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        # Production: JSON output
        processors = shared_processors + [
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Development: Pretty console output
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Reduce noise from third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger instance."""
    return structlog.get_logger(name)


# Convenience function for logging with context
def bind_context(**kwargs):
    """Bind context variables to current logger context."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context():
    """Clear all bound context variables."""
    structlog.contextvars.clear_contextvars()
