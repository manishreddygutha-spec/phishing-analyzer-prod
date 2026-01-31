# phishing_analyzer/logging_config.py

import logging
import sys

def setup_logging(level=logging.INFO):
    logger = logging.getLogger("phishing_analyzer")
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Prevent duplicate handlers

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False
    return logger
