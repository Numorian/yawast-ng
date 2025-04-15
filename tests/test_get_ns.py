#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from yawast.scanner.modules.dns import basic


class TestGetNs(TestCase):
    def test_get_ns(self):
        recs = basic.get_ns("adamcaudill.com")

        self.assertTrue(len(recs) > 0)

        for rec in recs:
            if rec.startswith("v"):
                self.assertEqual("vera.ns.cloudflare.com.", rec)
