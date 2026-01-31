import time
import logging
from functools import wraps

logger = logging.getLogger(__name__)


def resilient_call(retries=3, delay=1.0, backoff=2.0, exceptions=(Exception,)):
    """
    Decorator that retries a function with exponential backoff.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            wait = delay
            last_error = None

            for attempt in range(1, retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_error = e
                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt}/{retries}): {e}"
                    )

                    if attempt < retries:
                        time.sleep(wait)
                        wait *= backoff

            logger.error(f"{func.__name__} failed after {retries} retries")
            raise last_error

        return wrapper

    return decorator
