#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.shared import network


class TestCheckSslRedirect:
    def test_check_ssl_redirect_valid(self):
        assert (
            network.check_ssl_redirect("http://adamcaudill.com/")
            == "https://adamcaudill.com/"
        )

    def test_check_ssl_redirect_https(self):
        assert (
            network.check_ssl_redirect("https://adamcaudill.com/")
            == "https://adamcaudill.com/"
        )

    def test_check_ssl_redirect_none(self):
        assert (
            network.check_ssl_redirect("http://example.com/") == "http://example.com/"
        )

    def test_check_ssl_redirect_path(self):
        assert (
            network.check_ssl_redirect("http://mail.google.com/")
            == "https://mail.google.com/"
        )
