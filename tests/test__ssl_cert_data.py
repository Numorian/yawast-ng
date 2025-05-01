#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.ssl import cert_info
from yawast.scanner.modules.ssl.cert_info import _get_ct_log_data


class TestSslCertData:
    def test__get_ct_log_data(self):
        recs = _get_ct_log_data()
        assert len(recs) > 0

    def test_get_ct_log_name(self):
        assert (
            cert_info.get_ct_log_name(
                "a4501269055a15545e6211ab37bc103f62ae5576a45e4b1714453e1b22106a25"
            )
            == "Google 'Argon2018' log"
        )

    def test_get_ct_log_name_bad(self):
        assert cert_info.get_ct_log_name("ffffff") == "(Unknown: ffffff)"
