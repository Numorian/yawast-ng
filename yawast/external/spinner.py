# From: https://stackoverflow.com/a/39504463
# License: Creative Commons Attribution-Share Alike
# Copyright: Victor Moyseenko

import sys
import time
import threading


class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in "|/-\\":
                yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay):
            self.delay = delay

    def spinner_task(self):
        while self.busy:
            try:
                if sys.stdout.isatty():
                    sys.stdout.write(next(self.spinner_generator))
                    sys.stdout.flush()
                    time.sleep(self.delay)
                    sys.stdout.write("\b")
                    sys.stdout.flush()
            except Exception:
                # we don't care what happens here
                pass

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.delay)
        if exception is not None:
            return False
