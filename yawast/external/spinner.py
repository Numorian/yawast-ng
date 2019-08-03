# From: https://stackoverflow.com/a/39504463
# License: Creative Commons Attribution-Share Alike
# Copyright: Victor Moyseenko

import sys
import time
import threading


class Spinner:
    running = False
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
        self.running = False

    def start(self):
        self.running = True
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def stop(self, exception=None):
        self.busy = False
        time.sleep(self.delay)

        while self.running:
            pass
        sys.stdout.write(" ")
        sys.stdout.flush()
        sys.stdout.write("\b")
        sys.stdout.flush()

        if exception is not None:
            return False

    def __enter__(self):
        self.start()

        return self

    def __exit__(self, exception, value, tb):
        return self.stop(exception)
