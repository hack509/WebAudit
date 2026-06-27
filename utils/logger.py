"""
Centralized Logging for WebAudit.

Provides both file and console logging with rich formatting.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


_loggers: dict[str, logging.Logger] = {}
_initialized = False

LOG_DIR = Path("logs")
console = Console()


def setup_logger(
    level: int = logging.INFO,
    log_dir: Optional[str | Path] = None,
    verbose: bool = False,
) -> logging.Logger:
    """
    Initialize the root WebAudit logger.

    Args:
        level: Logging level.
        log_dir: Directory for log files.
        verbose: Enable DEBUG level if True.

    Returns:
        The configured root logger.
    """
    global _initialized

    if verbose:
        level = logging.DEBUG

    log_path = Path(log_dir) if log_dir else LOG_DIR
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"webaudit_{timestamp}.log"

    # Root logger
    root_logger = logging.getLogger("webaudit")
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # File handler — detailed logging
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Console handler — rich formatting
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
    )
    rich_handler.setLevel(level)
    root_logger.addHandler(rich_handler)

    _initialized = True
    root_logger.info(f"Logger initialized — log file: {log_file}")
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger for a specific module.

    Args:
        name: Module name (e.g., 'audit.backend').

    Returns:
        A configured child logger.
    """
    global _initialized

    if not _initialized:
        setup_logger()

    if name not in _loggers:
        _loggers[name] = logging.getLogger(f"webaudit.{name}")

    return _loggers[name]
