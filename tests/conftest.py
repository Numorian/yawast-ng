import multiprocessing.util
import warnings

import pytest


@pytest.fixture(autouse=True, scope="session")
def suppress_multiprocessing_debug():
    # Patch multiprocessing.util._logger to suppress debug output
    # we'll use a custom logger to avoid the debug output

    class CustomLogger:
        def debug(self, *args, **kwargs):
            pass

        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

        def critical(self, *args, **kwargs):
            pass

        def exception(self, *args, **kwargs):
            pass

        def log(self, *args, **kwargs):
            pass

        def addHandler(self, *args, **kwargs):
            pass

        def getEffectiveLevel(self):
            return 0

    # Set the custom logger to suppress debug output
    multiprocessing.util._logger = CustomLogger()
