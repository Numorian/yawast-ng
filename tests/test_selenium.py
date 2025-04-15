#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

from tests import utils
from yawast import command_line
from yawast.scanner.modules.http.applications.generic.password_reset import (
    _find_user_field,
    _get_driver,
)
from yawast.scanner.session import Session
from yawast.shared import output


class TestSeleniumIntegration(TestCase):
    def test_pwd_rst_get_driver(self):
        url = "https://example.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)

            try:
                driver = _get_driver(s, url)
            except Exception as error:
                self.assertIsNone(error)

            self.assertIsInstance(driver, WebDriver)
            self.assertIn("<h1>Example Domain</h1>", driver.page_source)
            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())

    def test_pwd_rst_find_field(self):
        url = "https://www.starbucks.com/account/forgot-password"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)

            try:
                driver = _get_driver(s, url)
                element = _find_user_field(driver)
            except Exception as error:
                self.assertIsNone(error)

            self.assertIsInstance(driver, WebDriver)
            self.assertIsInstance(element, WebElement)
            self.assertIn("Just need to confirm your email", driver.page_source)
            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertEqual("emailAddress", element.get_attribute("id"))
