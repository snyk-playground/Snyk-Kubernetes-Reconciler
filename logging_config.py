import logging.config
from pythonjsonlogger import jsonlogger
import os

LOG_LEVEL = os.getenv("LOG_LEVEL")

if not LOG_LEVEL:
    LOG_LEVEL = "INFO"
else:
    LOG_LEVEL = LOG_LEVEL.upper()
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": "%(asctime)s %(levelname)s %(message)s",
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
        }
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "json",
        }
    },
    "loggers": {"": {"handlers": ["stdout"], "level": LOG_LEVEL}},
}
logging.config.dictConfig(LOGGING)