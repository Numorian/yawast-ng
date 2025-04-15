#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from dns import resolver

from yawast.scanner.modules.dns.caa import _get_cname


class TestGetCname(TestCase):
    def test__get_cname(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        name = _get_cname("cntest.adamcaudill.com", resv)

        self.assertEqual("www.google.com.", name)
