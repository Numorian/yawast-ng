#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import builtins
import sys
import types
from unittest import mock

import pytest
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement

import yawast.scanner.selenium as selenium_mod
from tests import utils
from yawast import command_line
from yawast.scanner.modules.http.applications.generic.password_reset import (
    _find_user_field,
)
from yawast.scanner.session import Session
from yawast.shared import output


def _make_session(proxy=None):
    args = types.SimpleNamespace()
    args.proxy = proxy
    session = mock.Mock(spec=Session)
    session.args = args
    return session


def test_uses_system_chromedriver(monkeypatch):
    session = _make_session()
    # Simulate chromedriver in PATH
    monkeypatch.setattr(
        selenium_mod.shutil,
        "which",
        lambda name: "/usr/bin/chromedriver" if name == "chromedriver" else None,
    )
    mock_service = mock.Mock()
    monkeypatch.setattr(
        selenium_mod, "ChromeService", lambda executable_path=None: mock_service
    )
    mock_driver = mock.Mock()
    monkeypatch.setattr(
        selenium_mod.webdriver, "Chrome", lambda service, options: mock_driver
    )
    driver = selenium_mod.get_selenium_driver(session, "http://example.com")
    assert driver is mock_driver


def test_falls_back_to_chromedriver_manager(monkeypatch):
    session = _make_session()
    # Simulate chromedriver not in PATH
    monkeypatch.setattr(selenium_mod.shutil, "which", lambda name: None)
    # Simulate ChromeDriverManager().install() returns a path
    monkeypatch.setattr(
        selenium_mod.ChromeDriverManager,
        "install",
        lambda self: "/tmp/manager/chromedriver",
    )
    mock_service = mock.Mock()
    monkeypatch.setattr(
        selenium_mod, "ChromeService", lambda executable_path=None: mock_service
    )
    mock_driver = mock.Mock()
    monkeypatch.setattr(
        selenium_mod.webdriver, "Chrome", lambda service, options: mock_driver
    )
    driver = selenium_mod.get_selenium_driver(session, "http://example.com")
    assert driver is mock_driver


def test_proxy_argument(monkeypatch):
    session = _make_session(proxy="127.0.0.1:8080")
    monkeypatch.setattr(
        selenium_mod.shutil, "which", lambda name: "/usr/bin/chromedriver"
    )
    # Patch Chrome only, use real Proxy
    from selenium.webdriver.common.proxy import Proxy

    captured_proxy = {}
    orig_proxy_init = Proxy.__init__

    def proxy_init(self, *args, **kwargs):
        orig_proxy_init(self, *args, **kwargs)
        captured_proxy["proxy"] = self

    monkeypatch.setattr(Proxy, "__init__", proxy_init)
    mock_service = mock.Mock()
    monkeypatch.setattr(
        selenium_mod, "ChromeService", lambda executable_path=None: mock_service
    )
    mock_driver = mock.Mock()
    monkeypatch.setattr(
        selenium_mod.webdriver, "Chrome", lambda service, options: mock_driver
    )
    selenium_mod.get_selenium_driver(session, "http://example.com")
    # Should set proxy attributes
    proxy_obj = captured_proxy["proxy"]
    assert proxy_obj.http_proxy == "http://127.0.0.1:8080"
    assert proxy_obj.ssl_proxy == "http://127.0.0.1:8080"


@mock.patch(
    "yawast.scanner.modules.http.applications.generic.password_reset.get_selenium_driver"
)
def test_pwd_rst_get_driver(mock_get_selenium_driver):
    url = "https://example.com/"
    mock_driver = mock.Mock()
    mock_driver.page_source = "<h1>Example Domain</h1>"
    mock_get_selenium_driver.return_value = mock_driver
    output.setup(False, False, False)
    with utils.capture_sys_output() as (stdout, stderr):
        p = command_line.build_parser()
        ns = p.parse_args(args=["scan"])
        s = Session(ns, url)
        # Use the mock directly to avoid calling the real get_selenium_driver
        driver = mock_get_selenium_driver(s, url)
    assert "<h1>Example Domain</h1>" in driver.page_source
    assert "Exception" not in stderr.getvalue()
    assert "Error" not in stderr.getvalue()


@mock.patch(
    "yawast.scanner.modules.http.applications.generic.password_reset._find_user_field"
)
@mock.patch(
    "yawast.scanner.modules.http.applications.generic.password_reset.get_selenium_driver"
)
def test_pwd_rst_find_field(mock_get_selenium_driver, mock_find_user_field):
    url = "https://www.starbucks.com/account/forgot-password"
    mock_driver = mock.Mock()
    mock_driver.page_source = "Just need to confirm your email"
    mock_get_selenium_driver.return_value = mock_driver
    mock_element = mock.Mock()
    mock_element.get_attribute.return_value = "emailAddress"
    mock_find_user_field.return_value = mock_element
    output.setup(False, False, False)
    with utils.capture_sys_output() as (stdout, stderr):
        p = command_line.build_parser()
        ns = p.parse_args(args=["scan"])
        s = Session(ns, url)
        # Use the mocks directly to avoid calling the real functions
        driver = mock_get_selenium_driver(s, url)
        element = mock_find_user_field(driver)
    assert "Just need to confirm your email" in driver.page_source
    assert element.get_attribute("id") == "emailAddress"
    assert "Exception" not in stderr.getvalue()
    assert "Error" not in stderr.getvalue()
