from unittest import mock

import pytest

from yawast.scanner.modules.http import generic_login


class TestGenericLogin:
    @mock.patch("yawast.scanner.modules.http.generic_login.webdriver.Chrome")
    @mock.patch("yawast.scanner.modules.http.generic_login.ChromeDriverManager")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_element")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_login_link")
    @mock.patch("yawast.scanner.modules.http.generic_login._detect_login_error")
    @mock.patch("yawast.scanner.modules.http.generic_login.output")
    def test_successful_login_with_cookies_and_header(
        self,
        mock_output,
        mock_detect_login_error,
        mock_find_login_link,
        mock_find_element,
        mock_chromedriver_manager,
        mock_webdriver_chrome,
    ):
        # Setup mocks
        mock_driver = mock.Mock()
        mock_webdriver_chrome.return_value = mock_driver
        mock_chromedriver_manager().install.return_value = "/path/to/chromedriver"
        user_field = mock.Mock()
        pass_field = mock.Mock()
        submit_btn = mock.Mock()
        mock_find_element.side_effect = [user_field, pass_field, submit_btn]
        mock_find_login_link.return_value = None
        mock_detect_login_error.return_value = None

        # Simulate cookies and localStorage/sessionStorage
        mock_driver.get_cookies.return_value = [
            {"name": "sessionid", "value": "abc123"}
        ]
        mock_driver.execute_script.side_effect = [
            ["authorization"],  # localStorage keys
            "Bearer token",  # localStorage.getItem
            [],  # sessionStorage keys
        ]

        result = generic_login.login_and_get_auth("http://example.com", "user", "pass")

        assert result["cookies"] == {"sessionid": "abc123"}
        assert result["header"] == {"authorization": "Bearer token"}
        assert result["error"] is None
        mock_driver.quit.assert_called_once()

    @mock.patch("yawast.scanner.modules.http.generic_login.webdriver.Chrome")
    @mock.patch("yawast.scanner.modules.http.generic_login.ChromeDriverManager")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_element")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_login_link")
    @mock.patch("yawast.scanner.modules.http.generic_login._detect_login_error")
    @mock.patch("yawast.scanner.modules.http.generic_login.output")
    def test_login_fields_not_found_raises(
        self,
        mock_output,
        mock_detect_login_error,
        mock_find_login_link,
        mock_find_element,
        mock_chromedriver_manager,
        mock_webdriver_chrome,
    ):
        mock_driver = mock.Mock()
        mock_webdriver_chrome.return_value = mock_driver
        mock_chromedriver_manager().install.return_value = "/path/to/chromedriver"
        # No user/pass fields found, no login link found
        mock_find_element.side_effect = [None, None, None, None]
        mock_find_login_link.return_value = None

        with pytest.raises(generic_login.LoginFormNotFound):
            generic_login.login_and_get_auth("http://example.com", "user", "pass")
        mock_driver.quit.assert_called_once()

    @mock.patch("yawast.scanner.modules.http.generic_login.webdriver.Chrome")
    @mock.patch("yawast.scanner.modules.http.generic_login.ChromeDriverManager")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_element")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_login_link")
    @mock.patch("yawast.scanner.modules.http.generic_login._detect_login_error")
    @mock.patch("yawast.scanner.modules.http.generic_login.output")
    def test_login_with_error_message(
        self,
        mock_output,
        mock_detect_login_error,
        mock_find_login_link,
        mock_find_element,
        mock_chromedriver_manager,
        mock_webdriver_chrome,
    ):
        mock_driver = mock.Mock()
        mock_webdriver_chrome.return_value = mock_driver
        mock_chromedriver_manager().install.return_value = "/path/to/chromedriver"
        user_field = mock.Mock()
        pass_field = mock.Mock()
        submit_btn = mock.Mock()
        mock_find_element.side_effect = [user_field, pass_field, submit_btn]
        mock_find_login_link.return_value = None
        mock_detect_login_error.return_value = "Invalid password"
        mock_driver.get_cookies.return_value = []
        mock_driver.execute_script.side_effect = [
            [],  # localStorage keys
            [],  # sessionStorage keys
        ]

        result = generic_login.login_and_get_auth("http://example.com", "user", "pass")

        assert result["cookies"] == {}
        assert result["header"] is None
        assert result["error"] == "Invalid password"
        mock_driver.quit.assert_called_once()

    @mock.patch("yawast.scanner.modules.http.generic_login.webdriver.Chrome")
    @mock.patch("yawast.scanner.modules.http.generic_login.ChromeDriverManager")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_element")
    @mock.patch("yawast.scanner.modules.http.generic_login._find_login_link")
    @mock.patch("yawast.scanner.modules.http.generic_login._detect_login_error")
    @mock.patch("yawast.scanner.modules.http.generic_login.output")
    def test_login_fields_found_after_clicking_login_link(
        self,
        mock_output,
        mock_detect_login_error,
        mock_find_login_link,
        mock_find_element,
        mock_chromedriver_manager,
        mock_webdriver_chrome,
    ):
        mock_driver = mock.Mock()
        mock_webdriver_chrome.return_value = mock_driver
        mock_chromedriver_manager().install.return_value = "/path/to/chromedriver"
        # First attempt: no fields, after clicking login link: fields found
        user_field = mock.Mock()
        pass_field = mock.Mock()
        submit_btn = mock.Mock()
        login_link = mock.Mock()
        mock_find_element.side_effect = [None, None, user_field, pass_field, submit_btn]
        mock_find_login_link.return_value = login_link
        mock_detect_login_error.return_value = None
        mock_driver.get_cookies.return_value = []
        mock_driver.execute_script.side_effect = [
            [],  # localStorage keys
            [],  # sessionStorage keys
        ]

        result = generic_login.login_and_get_auth("http://example.com", "user", "pass")

        assert result["cookies"] == {}
        assert result["header"] is None
        assert result["error"] is None
        login_link.click.assert_called_once()
        mock_driver.quit.assert_called_once()


def make_mock_driver(
    user_found=True,
    pass_found=True,
    btn_found=True,
    login_link_found=False,
    error_text=None,
    cookies=None,
    header=None,
):
    driver = mock.Mock()
    # Mock user/pass fields
    user_field = mock.Mock()
    pass_field = mock.Mock()
    btn = mock.Mock()
    login_link = mock.Mock() if login_link_found else None

    # Field finding logic
    def find_element_side_effect(by, value):
        if any(n in value for n in generic_login.COMMON_USER_FIELDS) and user_found:
            return user_field
        if any(n in value for n in generic_login.COMMON_PASS_FIELDS) and pass_found:
            return pass_field
        if any(n in value for n in generic_login.COMMON_SUBMIT_BUTTONS) and btn_found:
            return btn
        if "body" in value:
            body = mock.Mock()
            body.text = error_text or ""
            return body
        raise Exception("not found")

    driver.find_element.side_effect = find_element_side_effect

    # Login link
    def find_login_link_side_effect(*a, **k):
        if login_link_found:
            return login_link
        raise Exception("not found")

    # Error detection
    driver.find_elements.side_effect = lambda by, sel: []
    # Cookies
    driver.get_cookies.return_value = cookies or []
    # JS storage
    driver.execute_script.side_effect = lambda script: (
        [] if "Object.keys" in script else None
    )
    # Displayed
    user_field.is_displayed.return_value = True
    pass_field.is_displayed.return_value = True
    btn.is_displayed.return_value = True
    if login_link:
        login_link.is_displayed.return_value = True
    # OuterHTML
    user_field.get_attribute.return_value = '<input name="user">'
    pass_field.get_attribute.return_value = '<input name="pass">'
    btn.get_attribute.return_value = '<button type="submit">'
    if login_link:
        login_link.get_attribute.return_value = "<a>login</a>"
    # Submit/click
    user_field.clear.return_value = None
    user_field.send_keys.return_value = None
    pass_field.clear.return_value = None
    pass_field.send_keys.return_value = None
    pass_field.submit.return_value = None
    btn.click.return_value = None
    if login_link:
        login_link.click.return_value = None
    return driver


def test_login_and_get_auth_success(monkeypatch):
    driver = make_mock_driver()
    monkeypatch.setattr("selenium.webdriver.Chrome", lambda *a, **k: driver)
    monkeypatch.setattr(
        "webdriver_manager.chrome.ChromeDriverManager",
        mock.Mock(install=lambda self: "/path/to/chromedriver"),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    result = generic_login.login_and_get_auth("http://example.com", "user", "pass")
    assert "cookies" in result and "header" in result and "error" in result


def test_login_and_get_auth_login_link(monkeypatch):
    # Simulate: first no fields, then after clicking login link, fields are found
    driver = make_mock_driver(user_found=False, pass_found=False, login_link_found=True)
    # Patch _find_element to return None, None, then user_field, pass_field, btn
    user_field = mock.Mock()
    user_field.is_displayed.return_value = True
    pass_field = mock.Mock()
    pass_field.is_displayed.return_value = True
    btn = mock.Mock()
    btn.is_displayed.return_value = True
    call_count = {"count": 0}

    def find_element_side_effect(driver_arg, names, type=None):
        if call_count["count"] < 2:
            call_count["count"] += 1
            return None
        if type == "submit" or type == "button":
            return btn
        if names == generic_login.COMMON_USER_FIELDS:
            return user_field
        if names == generic_login.COMMON_PASS_FIELDS:
            return pass_field
        return None

    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login._find_element",
        find_element_side_effect,
    )
    monkeypatch.setattr("selenium.webdriver.Chrome", lambda *a, **k: driver)
    monkeypatch.setattr(
        "webdriver_manager.chrome.ChromeDriverManager",
        mock.Mock(install=lambda self: "/path/to/chromedriver"),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login._detect_login_error", lambda d: None
    )
    result = generic_login.login_and_get_auth("http://example.com", "user", "pass")
    assert "cookies" in result
    driver.quit.assert_called_once()


def test_login_and_get_auth_no_fields(monkeypatch):
    driver = make_mock_driver(
        user_found=False, pass_found=False, login_link_found=False
    )
    monkeypatch.setattr("selenium.webdriver.Chrome", lambda *a, **k: driver)
    monkeypatch.setattr(
        "webdriver_manager.chrome.ChromeDriverManager",
        mock.Mock(install=lambda self: "/path/to/chromedriver"),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    with pytest.raises(generic_login.LoginFormNotFound):
        generic_login.login_and_get_auth("http://example.com", "user", "pass")


def test_find_element_found(monkeypatch):
    driver = make_mock_driver()
    el = generic_login._find_element(driver, ["user"])
    assert el is not None


def test_find_element_not_found(monkeypatch):
    driver = make_mock_driver(user_found=False)
    el = generic_login._find_element(driver, ["user"])
    assert el is None


def test_find_login_link_found(monkeypatch):
    driver = make_mock_driver(login_link_found=True)
    el = generic_login._find_login_link(driver)
    assert el is not None


def test_find_login_link_not_found(monkeypatch):
    driver = make_mock_driver(login_link_found=False)
    # Patch driver.find_element to always raise Exception
    driver.find_element.side_effect = Exception("not found")
    el = generic_login._find_login_link(driver)
    assert el is None


def test_detect_login_error(monkeypatch):
    driver = make_mock_driver(error_text="Invalid password")
    err = generic_login._detect_login_error(driver)
    assert err is not None


def test_detect_login_error_none(monkeypatch):
    driver = make_mock_driver(error_text="Welcome!")
    err = generic_login._detect_login_error(driver)
    assert err is None


def test_find_parent_form_found():
    el = mock.Mock()
    parent = mock.Mock()
    parent.tag_name = "form"
    el.find_element.side_effect = [parent]
    result = generic_login._find_parent_form(el)
    assert result == parent


def test_find_parent_form_not_found():
    el = mock.Mock()
    el.find_element.side_effect = Exception("fail")
    result = generic_login._find_parent_form(el)
    assert result is None
