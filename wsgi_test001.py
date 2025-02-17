import os
import sys
import traceback

log_file = "/tmp/viper_wsgi_debug.log"

# Ensure logging is written to a file
def log_debug(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

log_debug("===== Starting WSGI Application =====")
log_debug(f"Python Version: {sys.version}")
log_debug(f"Python Path: {sys.path}")
log_debug(f"Environment: {os.environ}")

try:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "viper_web.settings")
    log_debug(f"DJANGO_SETTINGS_MODULE set to: {os.environ['DJANGO_SETTINGS_MODULE']}")

    from django.core.wsgi import get_wsgi_application
    application = get_wsgi_application()
    log_debug("Django WSGI application loaded successfully")

except Exception:
    log_debug("ERROR OCCURRED!")
    log_debug(traceback.format_exc())
    raise
