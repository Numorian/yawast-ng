from unittest import TestCase
from yawast.shared import network


class TestCheckWwwRedirect(TestCase):
    def test_check_www_redirect_valid(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            network.check_www_redirect("https://www.adamcaudill.com/"),
        )

    def test_check_www_redirect_none(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            network.check_www_redirect("https://adamcaudill.com/"),
        )

    def test_check_www_redirect_www(self):
        self.assertEqual(
            "https://www.apple.com/", network.check_www_redirect("https://apple.com/")
        )
