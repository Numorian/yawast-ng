import unittest
from unittest import mock

import yawast.shared.network as network


class TestUpdateAuth(unittest.TestCase):
    def setUp(self):
        # Reset the session before each test
        network.reset()

    @mock.patch.object(network, "_requester")
    def test_update_auth_headers_equal(self, mock_requester):
        auth = {"headers": ["X-Test=Value"]}
        network.update_auth(auth)
        mock_requester.headers.update.assert_called_with({"X-Test": "Value"})

    @mock.patch.object(network, "_requester")
    def test_update_auth_headers_colon(self, mock_requester):
        auth = {"headers": ["X-Test: Value"]}
        network.update_auth(auth)
        mock_requester.headers.update.assert_called_with({"X-Test": "Value"})

    @mock.patch("yawast.shared.network.output")
    @mock.patch.object(network, "_requester")
    def test_update_auth_headers_invalid(self, mock_requester, mock_output):
        auth = {"headers": ["InvalidHeader"]}
        network.update_auth(auth)
        mock_output.error.assert_called_once()
        mock_requester.headers.update.assert_not_called()

    @mock.patch.object(network, "_requester")
    def test_update_auth_cookies(self, mock_requester):
        cookies = {"sessionid": "abc123", "userid": "42"}
        auth = {"cookies": cookies}
        with mock.patch("requests.cookies.create_cookie") as mock_create_cookie:
            mock_cookie = mock.Mock()
            mock_create_cookie.side_effect = lambda name, value: f"{name}={value}"
            network.update_auth(auth)
            calls = [
                mock.call(name="sessionid", value="abc123"),
                mock.call(name="userid", value="42"),
            ]
            mock_create_cookie.assert_has_calls(calls, any_order=True)
            mock_requester.cookies.set_cookie.assert_any_call("sessionid=abc123")
            mock_requester.cookies.set_cookie.assert_any_call("userid=42")

    def test_update_auth_empty(self):
        # Should not raise or do anything
        network.update_auth({})
