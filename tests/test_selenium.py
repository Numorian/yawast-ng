#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import mock

import pytest
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


class TestSelenium:
    @mock.patch(
        "yawast.scanner.modules.http.applications.generic.password_reset._get_driver"
    )
    def test_pwd_rst_get_driver(self, mock_get_driver):
        url = "https://example.com/"
        mock_driver = mock.Mock()
        mock_driver.page_source = "<h1>Example Domain</h1>"
        mock_get_driver.return_value = mock_driver
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)
            driver = _get_driver(s, url)
        assert "<h1>Example Domain</h1>" in driver.page_source
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stderr.getvalue()

    @mock.patch(
        "yawast.scanner.modules.http.applications.generic.password_reset._find_user_field"
    )
    @mock.patch(
        "yawast.scanner.modules.http.applications.generic.password_reset._get_driver"
    )
    def test_pwd_rst_find_field(self, mock_get_driver, mock_find_user_field):
        url = "https://www.starbucks.com/account/forgot-password"
        mock_driver = mock.Mock()
        mock_driver.page_source = "Just need to confirm your email"
        mock_get_driver.return_value = mock_driver
        mock_element = mock.Mock()
        mock_element.get_attribute.return_value = "emailAddress"
        mock_find_user_field.return_value = mock_element
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)
            driver = _get_driver(s, url)
            element = _find_user_field(driver)
        assert "Just need to confirm your email" in driver.page_source
        assert element.get_attribute("id") == "emailAddress"
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stderr.getvalue()
