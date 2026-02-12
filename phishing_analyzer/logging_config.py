import logging
import sys
from logging.handlers import RotatingFileHandler

def setup_logging(level=logging.INFO):
    logger = logging.getLogger("phishing_analyzer")
    logger.setLevel(level)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )

    # Console logging (existing behavior)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 🆕 File logging for observability (production requirement)
    file_handler = RotatingFileHandler(
        "system.log", maxBytes=2_000_000, backupCount=3
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger
