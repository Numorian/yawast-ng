# Copyright (c) 2025 Adam Caudill and Contributors.
# Unit tests for yawast/scanner/modules/http/applications/generic/password_reset.py
from unittest import mock

import pytest

from yawast.scanner.modules.http.applications.generic import password_reset


class DummyArgs:
    def __init__(self, pass_reset_page=None, proxy=None):
        self.pass_reset_page = pass_reset_page
        self.proxy = proxy


class DummySession:
    def __init__(self, pass_reset_page=None, proxy=None):
        self.args = DummyArgs(pass_reset_page, proxy)


def test_find_element_by_name_and_id():
    driver = mock.Mock()
    # Simulate find_element by name
    driver.find_element.side_effect = [mock.Mock(), Exception(), mock.Mock()]
    el = password_reset._find_element(driver, "user")
    assert el is not None


def test_find_user_field_with_name():
    driver = mock.Mock()
    el = mock.Mock()
    # Simulate direct match
    with mock.patch(
        "yawast.scanner.modules.http.applications.generic.password_reset._find_element",
        return_value=el,
    ):
        result = password_reset._find_user_field(driver, "custom")
        assert result == el


def test_find_user_field_no_match():
    driver = mock.Mock()
    # Simulate no match for any field
    with mock.patch(
        "yawast.scanner.modules.http.applications.generic.password_reset._find_element",
        return_value=None,
    ):
        with pytest.raises(password_reset.PasswordResetElementNotFound):
            password_reset._find_user_field(driver)


def test_fill_form_get_body(monkeypatch):
    session = DummySession(pass_reset_page="http://example.com")
    driver = mock.Mock()
    element = mock.Mock()
    element.is_displayed.return_value = True
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset._get_driver",
        lambda s, u: driver,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset._find_user_field",
        lambda d, n: element,
    )
    driver.page_source = "<html></html>"
    driver.get_screenshot_as_base64.return_value = "imgdata"
    element.send_keys.return_value = None
    element.submit.return_value = None
    driver.close.return_value = None
    res, img, delay = password_reset._fill_form_get_body(
        session, "http://example.com", "user"
    )
    assert res == "<html></html>"
    assert img == "imgdata"
    assert isinstance(delay, int)


def test_check_resp_user_enum(monkeypatch):
    session = DummySession(pass_reset_page="http://example.com")
    # Patch _fill_form_get_body to return different results for good/bad user
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset._fill_form_get_body",
        lambda s, u, user, e: (user, "img", 10 if "invalid" not in user else 30),
    )
    # Patch Result.from_evidence to just return a string for test
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: "result"
    )
    results = password_reset.check_resp_user_enum(session, "user")
    assert isinstance(results, list)
    assert "result" in results


def test_check_resp_user_enum_timing(monkeypatch):
    session = DummySession(pass_reset_page="http://example.com")
    # Patch _fill_form_get_body to return same response but different timing
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset._fill_form_get_body",
        lambda s, u, user, e: ("same", "img", 10 if "invalid" not in user else 30),
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: "timing"
    )
    results = password_reset.check_resp_user_enum(session, "user")
    assert "timing" in results


def test_check_resp_user_enum_exception(monkeypatch):
    session = DummySession(pass_reset_page="http://example.com")
    # Patch _fill_form_get_body to raise
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset._fill_form_get_body",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    with pytest.raises(Exception):
        password_reset.check_resp_user_enum(session, "user")


def test_get_driver_with_proxy(monkeypatch):
    session = DummySession(pass_reset_page="http://example.com", proxy="localhost:8080")
    # Patch all selenium and webdriver_manager classes used
    monkeypatch.setattr(
        "selenium.webdriver.Chrome", lambda *a, **k: mock.Mock(get=lambda uri: None)
    )
    monkeypatch.setattr(
        "selenium.webdriver.ChromeOptions",
        mock.Mock(
            return_value=mock.Mock(
                add_argument=lambda *a: None,
                add_experimental_option=lambda *a, **k: None,
                accept_insecure_certs=True,
            )
        ),
    )
    monkeypatch.setattr("selenium.webdriver.Proxy", mock.Mock)
    monkeypatch.setattr("selenium.webdriver.chrome.service.Service", mock.Mock)
    monkeypatch.setattr(
        "webdriver_manager.chrome.ChromeDriverManager",
        mock.Mock(install=lambda self: "/path/to/chromedriver"),
    )
    # Patch the logger used by webdriver_manager to ensure all handler.levels are ints
    import logging

    logger = logging.getLogger("WDM")
    for handler in list(logger.handlers):
        handler.level = logging.INFO
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)
    driver = password_reset._get_driver(session, "http://example.com")
    assert hasattr(driver, "get")
