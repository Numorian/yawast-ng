#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.http.servers import apache_httpd


class TestHttpApacheHttpd:
    def test_check_banner(self):
        res = apache_httpd.check_banner(
            "Apache", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 1
        assert res[0].message == "Generic Apache Server Banner Found"

    def test_check_banner_future(self):
        res = apache_httpd.check_banner(
            "Apache/99.9.9", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 1
        assert res[0].message == "Apache Server Version Exposed: Apache/99.9.9"

    def test_check_banner_old_24(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.7"
        assert "Apache Server Outdated:" in res[1].message

    def test_check_banner_old_php(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        assert len(res) == 4
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.6"
        assert "Apache Server Outdated:" in res[1].message
        assert res[2].message == "PHP Version Exposed: PHP/5.4.23"
        assert "PHP Outdated:" in res[3].message

    def test_check_banner_old_php_ossl(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23 OpenSSL/0.9.8n",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        assert len(res) == 5
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.6"
        assert "Apache Server Outdated:" in res[1].message
        assert res[2].message == "PHP Version Exposed: PHP/5.4.23"
        assert "PHP Outdated:" in res[3].message
        assert res[4].message == "OpenSSL Version Exposed: OpenSSL/0.9.8n"

    def test_check_banner_old_22(self):
        res = apache_httpd.check_banner(
            "Apache/2.2.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/2.2.7"
        assert "Apache Server Outdated:" in res[1].message

    def test_check_banner_old_invalid(self):
        res = apache_httpd.check_banner(
            "Apache/1.1.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/1.1.7"
        assert "Apache Server Outdated:" in res[1].message
