from unittest import TestCase
from yawast import main
from yawast._version import get_version
from tests import utils


class TestPrintHeader(TestCase):
    def test_print_header(self):
        with utils.capture_sys_output() as (stdout, stderr):
            main.print_header()

        self.assertIn("YAWAST v%s" % get_version(), stdout.getvalue())
