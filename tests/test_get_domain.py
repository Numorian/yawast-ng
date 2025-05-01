#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.shared.utils import get_domain


class TestGetDomain:
    def test_get_domain_clean(self):
        assert get_domain("adamcaudill.com") == "adamcaudill.com"

    def test_get_domain_http(self):
        assert get_domain("http://adamcaudill.com") == "adamcaudill.com"

    def test_get_domain_port(self):
        assert get_domain("adamcaudill.com:80") == "adamcaudill.com"

    def test_get_domain_creds(self):
        assert get_domain("user:pass@adamcaudill.com") == "adamcaudill.com"

    def test_get_domain_creds_port(self):
        assert get_domain("user:pass@adamcaudill.com:80") == "adamcaudill.com"

    def test_get_domain_ipv4_clean(self):
        assert get_domain("127.0.0.1") == "127.0.0.1"

    def test_get_domain_ipv4_port(self):
        assert get_domain("127.0.0.1:80") == "127.0.0.1"

    def test_get_domain_ipv4_creds_port(self):
        assert get_domain("user:pass@127.0.0.1:80") == "127.0.0.1"

    def test_get_domain_ipv6_clean(self):
        assert get_domain("[3ffe:2a00:100:7031::1]") == "[3ffe:2a00:100:7031::1]"

    def test_get_domain_ipv6_port(self):
        assert get_domain("[3ffe:2a00:100:7031::1]:80") == "[3ffe:2a00:100:7031::1]"
