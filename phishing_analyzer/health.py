import time
import platform
import logging

def run_health_check():
    status = {
        "status": "ok",
        "timestamp": time.time(),
        "python_version": platform.python_version(),
        "system": platform.system(),
    }

    try:
        import dns
        status["dns_available"] = True
    except Exception:
        status["dns_available"] = False

    try:
        import whois
        status["whois_available"] = True
    except Exception:
        status["whois_available"] = False

    logging.info("Health check executed")
    return status
