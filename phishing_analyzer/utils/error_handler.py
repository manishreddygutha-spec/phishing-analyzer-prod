import logging
import traceback

def safe_execute(step_name, func, *args, **kwargs):
    try:
        logging.info(f"Running step: {step_name}")
        return func(*args, **kwargs)
    except Exception as e:
        logging.error(f"Error in {step_name}: {str(e)}")
        logging.error(traceback.format_exc())
        return {
            "status": "error",
            "step": step_name,
            "message": str(e)
        }
