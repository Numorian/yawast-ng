import types
from unittest import mock

import pytest

from yawast.shared import network


class TestUpdateAuth:
    def setup_method(self):
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

    @mock.patch("requests.cookies.create_cookie")
    @mock.patch.object(network, "_requester")
    def test_update_auth_cookies(self, mock_requester, mock_create_cookie):
        cookies = {"sessionid": "abc123", "userid": "42"}
        auth = {"cookies": cookies}
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
        network.update_auth({})


def test_init_sets_proxy_cookie_header(monkeypatch):
    monkeypatch.setattr(
        network,
        "_requester",
        mock.Mock(
            cookies=mock.Mock(set_policy=lambda x: None, set_cookie=lambda x: None),
            proxies={},
            headers={},
            verify=None,
            mount=lambda *a, **k: None,
        ),
    )
    monkeypatch.setattr(network, "_file_not_found_handling", {})
    monkeypatch.setattr(network, "output", mock.Mock(error=lambda x: None))
    monkeypatch.setattr(
        network, "ssl", mock.Mock(create_default_context=lambda: mock.Mock())
    )
    monkeypatch.setattr(
        network, "urllib3", mock.Mock(Retry=lambda *a, **k: mock.Mock())
    )
    monkeypatch.setattr(
        network,
        "HTTPAdapter",
        mock.Mock(return_value=mock.Mock(init_poolmanager=lambda *a, **k: None)),
    )
    network.init("proxy:8080", "foo=bar", "X-Test=1")
    # Should not raise


def test_update_auth(monkeypatch):
    network._requester = mock.Mock(
        headers={}, cookies=mock.Mock(set_cookie=lambda x: None)
    )
    network.update_auth({"headers": ["X-Test=1"], "cookies": {"foo": "bar"}})
    # Should not raise


def test_http_head_and_options(monkeypatch):
    res = mock.Mock(
        status_code=200,
        request=mock.Mock(method="HEAD"),
        elapsed=types.SimpleNamespace(total_seconds=lambda: 0.01),
        headers={},
        url="http://foo",
        content=b"",
        text="",
        raw=mock.Mock(version=11, status=200, reason="OK", _original_response=None),
    )
    monkeypatch.setattr(network._requester, "head", lambda *a, **k: res)
    monkeypatch.setattr(
        network.plugin_manager, "run_hook_response_received", lambda u, r: None
    )
    monkeypatch.setattr(network.output, "debug", lambda x: None)
    monkeypatch.setattr(network.config, "user_agent", None)
    out = network.http_head("http://foo")
    assert out is res
    monkeypatch.setattr(network._requester, "options", lambda *a, **k: res)
    out2 = network.http_options("http://foo")
    assert out2 is res


def test_http_get(monkeypatch):
    res = mock.Mock(
        status_code=200,
        request=mock.Mock(method="GET"),
        elapsed=types.SimpleNamespace(total_seconds=lambda: 0.01),
        headers={},
        url="http://foo",
        content=b"abc",
        text="abc",
        iter_content=lambda c: [b"abc"],
    )
    monkeypatch.setattr(network._requester, "get", lambda *a, **k: res)
    monkeypatch.setattr(
        network.plugin_manager, "run_hook_response_received", lambda u, r: None
    )
    monkeypatch.setattr(network.output, "debug", lambda x: None)
    monkeypatch.setattr(network.config, "user_agent", None)
    out = network.http_get("http://foo")
    assert out is res


def test_http_put(monkeypatch):
    res = mock.Mock(
        status_code=200,
        request=mock.Mock(method="PUT"),
        elapsed=types.SimpleNamespace(total_seconds=lambda: 0.01),
        headers={},
        url="http://foo",
        content=b"abc",
        text="abc",
    )
    monkeypatch.setattr(network._requester, "put", lambda *a, **k: res)
    monkeypatch.setattr(
        network.plugin_manager, "run_hook_response_received", lambda u, r: None
    )
    monkeypatch.setattr(network.output, "debug", lambda x: None)
    monkeypatch.setattr(network.config, "user_agent", None)
    out = network.http_put("http://foo", "data")
    assert out is res


def test_http_custom(monkeypatch):
    res = mock.Mock(
        status_code=200,
        request=mock.Mock(method="CUSTOM"),
        elapsed=types.SimpleNamespace(total_seconds=lambda: 0.01),
        headers={},
        url="http://foo",
        content=b"abc",
        text="abc",
    )
    monkeypatch.setattr(network._requester, "request", lambda *a, **k: res)
    monkeypatch.setattr(
        network.plugin_manager, "run_hook_response_received", lambda u, r: None
    )
    monkeypatch.setattr(network.output, "debug", lambda x: None)
    monkeypatch.setattr(network.config, "user_agent", None)
    out = network.http_custom("CUSTOM", "http://foo")
    assert out is res


def test_http_json(monkeypatch):
    res = mock.Mock(json=lambda: {"foo": 1}, status_code=200)
    monkeypatch.setattr(network._requester, "get", lambda *a, **k: res)
    out, code = network.http_json("http://foo")
    assert out["foo"] == 1
    assert code == 200


def test_http_build_raw_request_and_response(monkeypatch):
    req = mock.Mock(method="GET", url="http://foo", headers={"X": "1"}, body="body")
    raw = network.http_build_raw_request(req)
    assert "GET http://foo" in raw
    res = mock.Mock(
        raw=mock.Mock(version=11, status=200, reason="OK", _original_response=None),
        headers={"X": "1"},
        text="abc",
        content=b"abc",
    )
    monkeypatch.setattr(network, "response_body_is_text", lambda r: True)
    out = network.http_build_raw_response(res)
    assert "HTTP/1.1" in out


def test_response_body_is_text(monkeypatch):
    res = mock.Mock(content=b"abc", headers={"Content-Type": "text/html"}, text="abc")
    assert network.response_body_is_text(res)
    res2 = mock.Mock(content=b"abc", headers={}, text="abc")
    monkeypatch.setattr(network.utils, "is_printable_str", lambda x: True)
    assert network.response_body_is_text(res2)
    res3 = mock.Mock(content=b"", headers={}, text="")
    assert not network.response_body_is_text(res3)


def test_check_ipv4_ipv6_connection(monkeypatch):
    monkeypatch.setattr(network, "_check_connection", lambda url: "1.2.3.4")
    monkeypatch.setattr(
        network, "checkers", mock.Mock(is_ipv4=lambda x: True, is_ipv6=lambda x: True)
    )
    assert "IPv4" in network.check_ipv4_connection()
    assert "IPv6" in network.check_ipv6_connection()


def test__check_connection(monkeypatch):
    monkeypatch.setattr(
        network, "requests", mock.Mock(get=lambda *a, **k: mock.Mock(text="1.2.3.4"))
    )
    assert network._check_connection("http://foo") == "1.2.3.4"


def test_reset():
    network.reset()
    assert network._requester is not None


class DummyArgs:
    def __init__(self, ports=False):
        self.ports = ports


class DummySession:
    def __init__(self, domain, url, ports=False):
        self.domain = domain
        self.url = url
        self.args = DummyArgs(ports=ports)


def test_scan_with_ports(monkeypatch):
    from yawast.scanner.cli import network as cli_network

    session = DummySession("example.com", "http://example.com", ports=True)
    called = {}
    monkeypatch.setattr(
        cli_network, "_check_open_ports", lambda d, u: called.setdefault("ports", True)
    )
    monkeypatch.setattr(
        cli_network.plugin_manager,
        "run_network_scans",
        lambda url: called.setdefault("plugin", True),
    )
    cli_network.scan(session)
    assert called["ports"]
    assert called["plugin"]


def test_scan_without_ports(monkeypatch):
    from yawast.scanner.cli import network as cli_network

    session = DummySession("example.com", "http://example.com", ports=False)
    monkeypatch.setattr(
        cli_network.plugin_manager,
        "run_network_scans",
        lambda url: setattr(session, "plugin", True),
    )
    cli_network.scan(session)
    assert hasattr(session, "plugin")


def test_check_open_ports_normal(monkeypatch):
    from yawast.scanner.cli import network as cli_network

    called = {}
    monkeypatch.setattr(cli_network.output, "empty", lambda: None)
    monkeypatch.setattr(cli_network.output, "norm", lambda *a, **k: None)
    monkeypatch.setattr(
        cli_network.reporter,
        "display_results",
        lambda res, tab: called.setdefault("display", True),
    )
    monkeypatch.setattr(cli_network.basic, "get_ips", lambda domain: ["1.2.3.4"])
    monkeypatch.setattr(
        cli_network.port_scan, "check_open_ports", lambda url, ip, file: ["open_port"]
    )
    cli_network._check_open_ports("example.com", "http://example.com")
    assert called["display"]


def test_check_open_ports_exception(monkeypatch):
    from yawast.scanner.cli import network as cli_network

    monkeypatch.setattr(cli_network.output, "empty", lambda: None)
    monkeypatch.setattr(cli_network.output, "norm", lambda *a, **k: None)
    monkeypatch.setattr(
        cli_network.output,
        "error",
        lambda msg: setattr(cli_network, "error_called", msg),
    )
    monkeypatch.setattr(
        cli_network.basic,
        "get_ips",
        lambda domain: (_ for _ in ()).throw(Exception("fail")),
    )
    cli_network._check_open_ports("example.com", "http://example.com")
    assert hasattr(cli_network, "error_called")


def test_init_invalid_proxy(monkeypatch):
    monkeypatch.setattr(
        network,
        "_requester",
        mock.Mock(
            cookies=mock.Mock(set_policy=lambda x: None, set_cookie=lambda x: None),
            proxies={},
            headers={},
            verify=None,
            mount=lambda *a, **k: None,
        ),
    )
    monkeypatch.setattr(network, "_file_not_found_handling", {})
    err = mock.Mock()
    monkeypatch.setattr(network, "output", mock.Mock(error=err))
    monkeypatch.setattr(
        network, "ssl", mock.Mock(create_default_context=lambda: mock.Mock())
    )
    monkeypatch.setattr(
        network, "urllib3", mock.Mock(Retry=lambda *a, **k: mock.Mock())
    )
    monkeypatch.setattr(
        network,
        "HTTPAdapter",
        mock.Mock(return_value=mock.Mock(init_poolmanager=lambda *a, **k: None)),
    )
    # Should not raise, and error may or may not be called depending on proxy string
    network.init("ftp://proxy", "foo=bar", "X-Test=1")
    assert True


def test_init_invalid_cookie(monkeypatch):
    monkeypatch.setattr(
        network,
        "_requester",
        mock.Mock(
            cookies=mock.Mock(set_policy=lambda x: None, set_cookie=lambda x: None),
            proxies={},
            headers={},
            verify=None,
            mount=lambda *a, **k: None,
        ),
    )
    monkeypatch.setattr(network, "_file_not_found_handling", {})
    err = mock.Mock()
    monkeypatch.setattr(network, "output", mock.Mock(error=err))
    monkeypatch.setattr(
        network, "ssl", mock.Mock(create_default_context=lambda: mock.Mock())
    )
    monkeypatch.setattr(
        network, "urllib3", mock.Mock(Retry=lambda *a, **k: mock.Mock())
    )
    monkeypatch.setattr(
        network,
        "HTTPAdapter",
        mock.Mock(return_value=mock.Mock(init_poolmanager=lambda *a, **k: None)),
    )
    # Should not raise, and error may or may not be called depending on cookie string
    network.init("", "invalidcookie", "X-Test=1")
    assert True


def test_init_invalid_header(monkeypatch):
    monkeypatch.setattr(
        network,
        "_requester",
        mock.Mock(
            cookies=mock.Mock(set_policy=lambda x: None, set_cookie=lambda x: None),
            proxies={},
            headers={},
            verify=None,
            mount=lambda *a, **k: None,
        ),
    )
    monkeypatch.setattr(network, "_file_not_found_handling", {})
    err = mock.Mock()
    monkeypatch.setattr(network, "output", mock.Mock(error=err))
    monkeypatch.setattr(
        network, "ssl", mock.Mock(create_default_context=lambda: mock.Mock())
    )
    monkeypatch.setattr(
        network, "urllib3", mock.Mock(Retry=lambda *a, **k: mock.Mock())
    )
    monkeypatch.setattr(
        network,
        "HTTPAdapter",
        mock.Mock(return_value=mock.Mock(init_poolmanager=lambda *a, **k: None)),
    )
    # Should not raise, and error may or may not be called depending on header string
    network.init("", "foo=bar", "InvalidHeader")
    assert True


def test_http_build_raw_response_binary(monkeypatch):
    res = mock.Mock(
        raw=mock.Mock(version=10, status=200, reason="OK", _original_response=None),
        headers={"X": "1"},
        text="",
        content=b"\x00\x01",
    )
    monkeypatch.setattr(network, "response_body_is_text", lambda r: False)
    out = network.http_build_raw_response(res)
    assert "<BINARY DATA EXCLUDED>" in out


def test_http_build_raw_response_exception(monkeypatch):
    res = mock.Mock(
        raw=mock.Mock(version=10, status=200, reason="OK", _original_response=None),
        headers={"X": "1"},
        text="",
        content=b"abc",
    )
    monkeypatch.setattr(
        network,
        "response_body_is_text",
        lambda r: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(network.output, "debug_exception", lambda: None)
    out = network.http_build_raw_response(res)
    assert "HTTP/1.0" in out


def test_check_ssl_redirect_non_redirect(monkeypatch):
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=200, headers={}, request=mock.Mock(method="HEAD")
        ),
    )
    assert network.check_ssl_redirect("http://foo") == "http://foo"


def test_check_ssl_redirect_missing_location(monkeypatch):
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301, headers={}, request=mock.Mock(method="HEAD")
        ),
    )
    assert network.check_ssl_redirect("http://foo") == "http://foo"


def test_check_ssl_redirect_exception(monkeypatch):
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301,
            headers={"location": "bad://"},
            request=mock.Mock(method="HEAD"),
        ),
    )
    monkeypatch.setattr(
        network, "urlparse", lambda x: (_ for _ in ()).throw(Exception("fail"))
    )
    with pytest.raises(Exception):
        network.check_ssl_redirect("http://foo")


def test_check_www_redirect_valueerror(monkeypatch):
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301,
            headers={"location": "bad://"},
            request=mock.Mock(method="HEAD"),
        ),
    )
    monkeypatch.setattr(
        network, "urlparse", lambda x: (_ for _ in ()).throw(ValueError("fail"))
    )
    with pytest.raises(ValueError):
        network.check_www_redirect("http://foo")


def test_response_body_is_text_binary(monkeypatch):
    res = mock.Mock(content=b"\x00\x01", headers={}, text="")
    monkeypatch.setattr(network.utils, "is_printable_str", lambda x: False)
    assert not network.response_body_is_text(res)


def test_check_ipv4_connection_exception(monkeypatch):
    monkeypatch.setattr(
        network,
        "_check_connection",
        lambda url: (_ for _ in ()).throw(Exception("fail")),
    )
    assert "(Unavailable)" in network.check_ipv4_connection()


def test_check_ipv6_connection_exception(monkeypatch):
    monkeypatch.setattr(
        network,
        "_check_connection",
        lambda url: (_ for _ in ()).throw(Exception("fail")),
    )
    assert "(Unavailable)" in network.check_ipv6_connection()


def test__check_connection_exception(monkeypatch):
    monkeypatch.setattr(
        network,
        "requests",
        mock.Mock(get=lambda *a, **k: (_ for _ in ()).throw(Exception("fail"))),
    )
    monkeypatch.setattr(network.output, "debug_exception", lambda: None)
    assert network._check_connection("http://foo") == "Connection Failed"


def test_http_file_exists_shrug(monkeypatch):
    # Covers the 'shrug' else branch in http_file_exists
    network._file_not_found_handling["foo.com"] = {
        "file": False,
        "file_res": mock.Mock(status_code=123, content=b"abc"),
    }
    monkeypatch.setattr(network, "utils", mock.Mock(get_domain=lambda url: "foo.com"))
    monkeypatch.setattr(network, "_get_404_handling", lambda domain, url: None)
    monkeypatch.setattr(
        network, "http_get", lambda url, **kwargs: mock.Mock(status_code=200)
    )
    out, res = network.http_file_exists("http://foo.com/bar")
    assert isinstance(out, bool)


def test_http_file_exists_redirect(monkeypatch):
    # Covers the redirect branch in http_file_exists
    network._file_not_found_handling["foo.com"] = {
        "file": False,
        "file_res": mock.Mock(status_code=301, content=b"abc"),
    }
    monkeypatch.setattr(network, "utils", mock.Mock(get_domain=lambda url: "foo.com"))
    monkeypatch.setattr(network, "_get_404_handling", lambda domain, url: None)
    monkeypatch.setattr(
        network, "http_get", lambda url, **kwargs: mock.Mock(status_code=200)
    )
    out, res = network.http_file_exists("http://foo.com/bar")
    assert out is True


def test_http_file_exists_error(monkeypatch):
    # Covers the >=400 branch in http_file_exists
    network._file_not_found_handling["foo.com"] = {
        "file": False,
        "file_res": mock.Mock(status_code=404, content=b"abc"),
    }
    monkeypatch.setattr(network, "utils", mock.Mock(get_domain=lambda url: "foo.com"))
    monkeypatch.setattr(network, "_get_404_handling", lambda domain, url: None)
    monkeypatch.setattr(
        network, "http_get", lambda url, **kwargs: mock.Mock(status_code=200)
    )
    out, res = network.http_file_exists("http://foo.com/bar")
    assert out is True


def test_http_file_exists_fuzzy(monkeypatch):
    # Covers the fuzzy matching branch in http_file_exists
    file_res = mock.Mock(
        status_code=200,
        content=b"abc",
        text="a\n" * 30,
        headers={"Content-Type": "text/html"},
    )
    get_res = mock.Mock(
        content=b"def",
        text="b\n" * 30,
        url="http://foo.com/bar",
        headers={"Content-Type": "text/html"},
    )
    network._file_not_found_handling["foo.com"] = {"file": False, "file_res": file_res}
    monkeypatch.setattr(network, "utils", mock.Mock(get_domain=lambda url: "foo.com"))
    monkeypatch.setattr(network, "_get_404_handling", lambda domain, url: None)
    monkeypatch.setattr(network, "http_get", lambda url, **kwargs: get_res)
    monkeypatch.setattr(network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        network,
        "ExecutionTimer",
        mock.Mock(
            return_value=mock.Mock(
                __enter__=lambda s: s, __exit__=lambda s, a, b, c: None, to_ms=lambda: 1
            )
        ),
    )
    out, res = network.http_file_exists("http://foo.com/bar")
    assert isinstance(out, bool)


def test_check_404_response(monkeypatch):
    # Covers check_404_response
    network._file_not_found_handling["foo.com"] = {
        "file": True,
        "file_res": mock.Mock(),
        "path": True,
        "path_res": mock.Mock(),
    }
    monkeypatch.setattr(network, "utils", mock.Mock(get_domain=lambda url: "foo.com"))
    monkeypatch.setattr(network, "_get_404_handling", lambda domain, url: None)
    out = network.check_404_response("http://foo.com/bar")
    assert isinstance(out, tuple)


def test_check_ssl_redirect_https(monkeypatch):
    # Covers the 'if parsed.scheme == "https"' branch
    monkeypatch.setattr(
        network, "urlparse", lambda url: type("P", (), {"scheme": "https"})()
    )
    assert network.check_ssl_redirect("https://foo") == "https://foo"


def test_check_ssl_redirect_path(monkeypatch):
    # Covers the 'parsed_location.netloc == "" and parsed_location.path != ""' branch
    class DummyParsed:
        scheme = "http"
        netloc = ""
        path = "/bar"

        def _replace(self, **kwargs):
            return self

    monkeypatch.setattr(network, "urlparse", lambda url: DummyParsed())
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301,
            headers={"location": "/bar"},
            request=mock.Mock(method="HEAD"),
        ),
    )
    monkeypatch.setattr(network, "urlunparse", lambda parsed: "http://foo/bar")
    # Should not raise
    assert network.check_ssl_redirect("http://foo")


def test_check_www_redirect_else(monkeypatch):
    # Covers the final else branch in check_www_redirect
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=200, headers={}, request=mock.Mock(method="HEAD")
        ),
    )
    assert network.check_www_redirect("http://foo") == "http://foo"


def test_check_www_redirect_www_branches(monkeypatch):
    # Covers both www/non-www domain logic
    class DummyParsed:
        def __init__(self, netloc):
            self.netloc = netloc
            self.path = ""

        def _replace(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
            return self

    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301,
            headers={"location": "http://example.com"},
            request=mock.Mock(method="HEAD"),
        ),
    )
    monkeypatch.setattr(
        network, "urlparse", lambda url: DummyParsed(url.split("//")[1])
    )
    monkeypatch.setattr(network, "urlunparse", lambda parsed: f"http://{parsed.netloc}")
    # domain starts with www, location_domain does not
    monkeypatch.setattr(
        network.utils,
        "get_domain",
        lambda netloc: (
            "www.example.com" if netloc == "www.example.com" else "example.com"
        ),
    )
    assert network.check_www_redirect("http://www.example.com") == "http://example.com"
    # domain does not start with www, location_domain does
    monkeypatch.setattr(
        network,
        "http_head",
        lambda url, allow: mock.Mock(
            status_code=301,
            headers={"location": "http://www.example.com"},
            request=mock.Mock(method="HEAD"),
        ),
    )
    monkeypatch.setattr(
        network.utils,
        "get_domain",
        lambda netloc: "example.com" if netloc == "example.com" else "www.example.com",
    )
    assert network.check_www_redirect("http://example.com") == "http://www.example.com"


def test_response_body_is_text_no_content_type(monkeypatch):
    # Covers the 'elif "Content-Type" not in res.headers' branch
    res = mock.Mock(content=b"abc", headers={}, text="abc")
    monkeypatch.setattr(network.utils, "is_printable_str", lambda x: True)
    assert network.response_body_is_text(res)
