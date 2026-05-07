"""Safe exit helpers for controlled application shutdown."""

from __future__ import annotations

import logging

from src.utils.console import print_message


def safe_exit(logger: logging.Logger, code: int = 0, message: str = "Safe exit") -> int:
    """Log a controlled exit message and return the exit code.

    Expects a logger, an exit code, and a short message. The helper keeps exit
    handling consistent so the app can stop cleanly without duplicating logging
    logic across multiple branches.
    """
    if code == 0:
        logger.info(message)
    elif code == 1:
        logger.warning(message)
    else:
        logger.error(message)
    print_message(message)
    return code
