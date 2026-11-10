import os

from foxess_local_cloud.server import JsonLogger

# Keep the daemon's JSON event lines out of the test runner output.
JsonLogger.console_stream = open(os.devnull, "w", encoding="utf-8")
