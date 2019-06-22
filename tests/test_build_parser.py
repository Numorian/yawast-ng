from unittest import TestCase
from yawast import command_line
from tests import utils


class TestBuildParser(TestCase):
    def test_build_parser(self):
        parser = command_line.build_parser()

        # make sure we got something back
        self.assertIsNotNone(parser)

        with self.assertRaises(SystemExit) as cm:
            with utils.capture_sys_output() as (stdout, stderr):
                parser.parse_known_args([""])

        self.assertIn("yawast: error", stderr.getvalue())
