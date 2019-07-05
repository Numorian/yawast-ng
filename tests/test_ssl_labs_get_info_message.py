from unittest import TestCase
from tests import utils
from yawast.shared import output
from yawast.scanner.plugins.ssl_labs import api


class TestGetInfoMessage(TestCase):
    def test_get_info_message(self):
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            recs = api.get_info_message()

        self.assertNotIn("Exception", stderr.getvalue())
        self.assertTrue(len(recs) > 0)
