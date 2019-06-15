from unittest import TestCase
from yawast.scanner.plugins.dns import srv
import os


class TestFindSrvRecords(TestCase):
    def test_find_srv_records(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "test_data/srv.txt")

        recs = srv.find_srv_records("adamcaudill.com", path)

        self.assertTrue(len(recs) > 0)
