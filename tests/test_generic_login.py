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
