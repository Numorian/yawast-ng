#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.shared import utils


class TestExtractUrl:
    def test_extract_url_clean(self):
        assert (
            utils.extract_url("https://adamcaudill.com/") == "https://adamcaudill.com/"
        )

    def test_extract_url_clean_port(self):
        assert (
            utils.extract_url("https://adamcaudill.com:8080/")
            == "https://adamcaudill.com:8080/"
        )

    def test_extract_url_clean_creds(self):
        assert (
            utils.extract_url("https://user:pass@adamcaudill.com/")
            == "https://user:pass@adamcaudill.com/"
        )

    def test_extract_url_clean_wss(self):
        assert utils.extract_url("wss://adamcaudill.com/") == "wss://adamcaudill.com/"

    def test_extract_url_path(self):
        assert (
            utils.extract_url("https://adamcaudill.com/t/")
            == "https://adamcaudill.com/t/"
        )

    def test_extract_url_path_upper(self):
        assert (
            utils.extract_url("HTTPS://ADAMCAUDILL.COM/T/")
            == "https://adamcaudill.com/T/"
        )

    def test_extract_url_missing_colon(self):
        assert (
            utils.extract_url("https//adamcaudill.com/") == "https://adamcaudill.com/"
        )

    def test_extract_url_missing_slash(self):
        assert (
            utils.extract_url("https:/adamcaudill.com/") == "https://adamcaudill.com/"
        )

    def test_extract_url_extra_slash(self):
        assert (
            utils.extract_url("https:///adamcaudill.com/") == "https://adamcaudill.com/"
        )

    def test_extract_url_extra_extra_slash(self):
        assert (
            utils.extract_url("https:////adamcaudill.com/")
            == "https://adamcaudill.com/"
        )

    def test_extract_url_missing_path(self):
        assert (
            utils.extract_url("https://adamcaudill.com") == "https://adamcaudill.com/"
        )

    def test_extract_url_file_name(self):
        assert (
            utils.extract_url("https://adamcaudill.com/index.html")
            == "https://adamcaudill.com/"
        )

    def test_extract_url_file_path(self):
        assert (
            utils.extract_url("https://adamcaudill.com/t/index.html")
            == "https://adamcaudill.com/t/"
        )

    def test_extract_url_query(self):
        assert (
            utils.extract_url("https://adamcaudill.com/?1=2")
            == "https://adamcaudill.com/"
        )

    def test_extract_url_query_path_file(self):
        assert (
            utils.extract_url("https://adamcaudill.com/t/x.php?1=2")
            == "https://adamcaudill.com/t/"
        )

    def test_extract_url_fragment(self):
        assert (
            utils.extract_url("https://adamcaudill.com/#1")
            == "https://adamcaudill.com/"
        )

    def test_extract_url_parameter(self):
        assert (
            utils.extract_url("https://adamcaudill.com/a;b")
            == "https://adamcaudill.com/"
        )

    def test_extract_url_ipv4(self):
        assert utils.extract_url("https://127.0.0.1") == "https://127.0.0.1/"

    def test_extract_url_ipv6(self):
        assert utils.extract_url("https://[2001::1]") == "https://[2001::1]/"

    def test_extract_url_idn(self):
        assert utils.extract_url("https://Bücher.example") == "https://bücher.example/"

    def test_extract_url_punnycode(self):
        assert (
            utils.extract_url("https://xn--bcher-kva.example")
            == "https://xn--bcher-kva.example/"
        )
