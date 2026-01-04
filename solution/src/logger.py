#!/usr/bin/env python3
"""Centralized logging configuration for the vulnerability RAG system.

Configurable via environment variables:
  LOG_LEVEL: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.
  LOG_FORMAT: Log format (json, simple). Defaults to simple.
"""

import json
import logging
import os
import sys


class SimpleFormatter(logging.Formatter):
    """Simple formatter with support for extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional extra fields."""
        # Base message
        msg = super().format(record)
        
        # Add extra fields if present (all fields except standard ones)
        standard_fields = {
            'name', 'msg', 'args', 'created', 'filename', 'funcName', 'levelname',
            'levelno', 'lineno', 'module', 'msecs', 'message', 'pathname', 'process',
            'processName', 'relativeCreated', 'thread', 'threadName', 'exc_info',
            'exc_text', 'stack_info', 'taskName', 'getMessage'
        }
        
        extra_fields = {k: v for k, v in record.__dict__.items() if k not in standard_fields}
        
        if extra_fields:
            # Format extra fields nicely
            extra_str = " | ".join(f"{k}={v}" for k, v in sorted(extra_fields.items()))
            msg = f"{msg} | {extra_str}"
        
        return msg


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger with centralized configuration.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if not already configured (avoid duplicate handlers)
    if not logger.handlers:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        log_format = os.getenv("LOG_FORMAT", "simple").lower()

        # Set log level
        try:
            logger.setLevel(getattr(logging, log_level))
        except AttributeError:
            logger.setLevel(logging.INFO)

        # Create console handler
        handler = logging.StreamHandler(sys.stdout)

        # Configure formatter
        if log_format == "json":
            formatter = JSONFormatter()
        else:
            # Simple format: [timestamp] logger_name - LEVEL - message [extra fields]
            formatter = SimpleFormatter(
                "[%(asctime)s] %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )

        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
