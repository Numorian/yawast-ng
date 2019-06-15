from unittest import TestCase
from yawast.scanner.plugins.dns import basic


class TestGetText(TestCase):
    def test_get_text(self):
        recs = basic.get_text("adamcaudill.com")

        self.assertTrue(len(recs) > 0)

        for rec in recs:
            if rec.startswith("v="):
                self.assertEqual("v=spf1 mx a ptr include:_spf.google.com ~all", rec)
