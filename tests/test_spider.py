from unittest import mock

import pytest

from yawast.scanner.modules.http import spider


class DummySession:
    def __init__(self):
        self.url = "http://example.com"
        self.args = mock.Mock(php_page=None)


def test_start_scan_invalid_sitemap(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 but invalid XML
    res = mock.Mock(status_code=200, text="<notxml>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)


def test_start_scan_empty_sitemap(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 with no <loc> tags
    res = mock.Mock(status_code=200, text="<urlset></urlset>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should handle empty sitemap
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)


def test_get_links_network_exception(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    monkeypatch.setattr(
        spider.network,
        "http_get",
        lambda url, allow: (_ for _ in ()).throw(Exception("fail")),
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise
    spider._get_links(session, session.url, [session.url], queue, pool)


def test_get_links_insecure_link(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    res = mock.Mock(
        status_code=200,
        text="<html><a href='http://insecure.com'>insecure</a></html>",
        headers={},
    )
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider.BeautifulSoup,
        "find_all",
        lambda self, tag: [
            mock.Mock(get=lambda k: "http://insecure.com", string="insecure")
        ],
    )
    monkeypatch.setattr(
        spider,
        "BeautifulSoup",
        lambda text, parser: mock.Mock(
            find_all=lambda tag: [
                mock.Mock(get=lambda k: "http://insecure.com", string="insecure")
            ]
        ),
    )
    queue = mock.Mock(put=lambda x: None)
    session.url = "https://secure.com"
    # Should not raise, should detect insecure link
    spider._get_links(session, session.url, [session.url], queue, pool)


def test_get_links_redirect(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    res = mock.Mock(
        status_code=200,
        text="<html></html>",
        headers={"Location": "/redirected"},
    )
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider, "BeautifulSoup", lambda text, parser: mock.Mock(find_all=lambda tag: [])
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should handle redirect
    spider._get_links(session, session.url, [session.url], queue, pool)


def test_is_unsafe_link_exception(monkeypatch):
    # Simulate exception in str(description)
    monkeypatch.setattr(spider, "output", mock.Mock(debug_exception=lambda: None))

    class Bad:
        def __str__(self):
            raise Exception("fail")

    # Should not raise, should return False
    assert spider.is_unsafe_link("/foo", Bad()) is False


def test_is_unsafe_link_detects(monkeypatch):
    # Should return True for unsafe fragments
    assert spider.is_unsafe_link("/logout", "logout") is True
    assert spider.is_unsafe_link("/foo", "delete") is True
    assert spider.is_unsafe_link("/foo", "destroy") is True
    assert spider.is_unsafe_link("/logoff", "") is True
    assert spider.is_unsafe_link("/foo", "log out") is True
    assert spider.is_unsafe_link("/foo", "log_off") is True
    assert spider.is_unsafe_link("/foo", "log out") is True
    assert spider.is_unsafe_link("/foo", "log_out") is True


def test_get_links_file_ext_filter(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    # Simulate network.http_get returns a response with text/html
    res = mock.Mock(
        status_code=200,
        text="<html><a href='http://example.com/file.jpg'>img</a><a href='http://example.com/file.php'>php</a></html>",
        headers={},
    )
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider.BeautifulSoup,
        "find_all",
        lambda self, tag: [
            mock.Mock(get=lambda k: "http://example.com/file.jpg", string="img"),
            mock.Mock(get=lambda k: "http://example.com/file.php", string="php"),
        ],
    )
    monkeypatch.setattr(
        spider,
        "BeautifulSoup",
        lambda text, parser: mock.Mock(
            find_all=lambda tag: [
                mock.Mock(get=lambda k: "http://example.com/file.jpg", string="img"),
                mock.Mock(get=lambda k: "http://example.com/file.php", string="php"),
            ]
        ),
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise
    spider._get_links(session, session.url, [session.url], queue, pool)


def test_get_links_max_pages(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        spider, "_links", list(range(spider.config.max_spider_pages + 1))
    )
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should early return
    spider._get_links(session, session.url, [session.url], queue, pool)


def test_spider_task_exception(monkeypatch):
    session = DummySession()

    # Simulate a task that raises on get()
    class FakeTask:
        def ready(self):
            return True

        def get(self):
            raise Exception("fail")

    fake_task = FakeTask()
    monkeypatch.setattr(spider, "_tasks", [fake_task])
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    lock = mock.MagicMock()
    lock.__enter__.return_value = None
    lock.__exit__.return_value = None
    monkeypatch.setattr(spider, "_lock", lock)
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    monkeypatch.setattr(
        spider,
        "Pool",
        lambda n: mock.Mock(apply_async=lambda *a, **k: fake_task, close=lambda: None),
    )
    monkeypatch.setattr(
        spider,
        "Manager",
        lambda: mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: [])),
    )
    session.url = "http://example.com"
    # Should not raise, should call debug_exception
    spider.spider(session)


def test_start_scan_weird_xml(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 with weird structure
    res = mock.Mock(status_code=200, text="<urlset><weirdtag>foo</weirdtag></urlset>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=lambda: None)
    )
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should handle weird XML
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)


def test_get_links_exception_in_loop(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    dbg = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=lambda x: None, debug_exception=dbg)
    )

    # Simulate network.http_get raises on second call
    def http_get_side_effect(url, allow):
        if hasattr(http_get_side_effect, "called"):
            raise Exception("fail")
        http_get_side_effect.called = True
        return mock.Mock(status_code=200, text="<html></html>", headers={})

    monkeypatch.setattr(spider.network, "http_get", http_get_side_effect)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider, "BeautifulSoup", lambda text, parser: mock.Mock(find_all=lambda tag: [])
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should call debug_exception
    spider._get_links(session, session.url, [session.url, session.url], queue, pool)


def test_get_links_debug_output(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    dbg = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=dbg, debug_exception=lambda: None)
    )
    res = mock.Mock(status_code=200, text="<html></html>", headers={})
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider, "BeautifulSoup", lambda text, parser: mock.Mock(find_all=lambda tag: [])
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should call debug output
    spider._get_links(session, session.url, [session.url], queue, pool)
    assert dbg.called


def test_spider_status_debug(monkeypatch):
    session = DummySession()

    # Simulate a task that is not ready on first call, then ready
    class FakeTask:
        def __init__(self):
            self.calls = 0

        def ready(self):
            self.calls += 1
            return self.calls > 1

    fake_task = FakeTask()
    monkeypatch.setattr(spider, "_tasks", [fake_task])
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    lock = mock.MagicMock()
    lock.__enter__.return_value = None
    lock.__exit__.return_value = None
    monkeypatch.setattr(spider, "_lock", lock)
    debug = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    monkeypatch.setattr(
        spider,
        "Pool",
        lambda n: mock.Mock(apply_async=lambda *a, **k: fake_task, close=lambda: None),
    )
    monkeypatch.setattr(
        spider,
        "Manager",
        lambda: mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: [])),
    )
    monkeypatch.setattr(spider, "time", mock.Mock(sleep=lambda x: None))
    session.url = "http://example.com"
    # Should not hang, should call debug for status
    spider.spider(session)
    assert debug.called


def test_start_scan_no_loc(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 with <urlset> but no <loc> tags
    res = mock.Mock(status_code=200, text="<urlset><url><foo>bar</foo></url></urlset>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    debug = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should call debug for no URLs found
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)
    assert debug.called


def test_start_scan_malformed_xml(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 with malformed XML
    res = mock.Mock(status_code=200, text="<urlset><url><loc>foo</url></urlset>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    debug_exception = mock.Mock()
    monkeypatch.setattr(
        spider,
        "output",
        mock.Mock(debug=lambda x: None, debug_exception=debug_exception),
    )
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should call debug_exception
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)
    assert debug_exception.called


def test_get_links_exception(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    debug_exception = mock.Mock()
    monkeypatch.setattr(
        spider,
        "output",
        mock.Mock(debug=lambda x: None, debug_exception=debug_exception),
    )

    # Simulate exception in for url in urls
    def raise_exc(url, allow):
        raise Exception("fail")

    monkeypatch.setattr(spider.network, "http_get", raise_exc)
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should call debug_exception
    spider._get_links(session, session.url, [session.url], queue, pool)
    assert debug_exception.called


def test_get_links_final_debug(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    debug = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    res = mock.Mock(status_code=200, text="<html></html>", headers={})
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    monkeypatch.setattr(spider.network, "response_body_is_text", lambda r: True)
    monkeypatch.setattr(
        spider.response_scanner, "check_response", lambda url, res, soup: []
    )
    monkeypatch.setattr(spider.utils, "fix_relative_link", lambda href, url: href)
    monkeypatch.setattr(
        spider, "BeautifulSoup", lambda text, parser: mock.Mock(find_all=lambda tag: [])
    )
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should call debug at end
    spider._get_links(session, session.url, [session.url], queue, pool)
    assert debug.called


def test_spider_status_debug_multiple_tasks(monkeypatch):
    session = DummySession()

    # Simulate two tasks: one not ready, one ready, then both ready
    class FakeTask:
        def __init__(self, ready_on=2):
            self.calls = 0
            self.ready_on = ready_on

        def ready(self):
            self.calls += 1
            return self.calls >= self.ready_on

    fake_task1 = FakeTask(ready_on=2)
    fake_task2 = FakeTask(ready_on=1)
    monkeypatch.setattr(spider, "_tasks", [fake_task1, fake_task2])
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    lock = mock.MagicMock()
    lock.__enter__.return_value = None
    lock.__exit__.return_value = None
    monkeypatch.setattr(spider, "_lock", lock)
    debug = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    monkeypatch.setattr(
        spider,
        "Pool",
        lambda n: mock.Mock(apply_async=lambda *a, **k: fake_task1, close=lambda: None),
    )
    monkeypatch.setattr(
        spider,
        "Manager",
        lambda: mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: [])),
    )
    monkeypatch.setattr(spider, "time", mock.Mock(sleep=lambda x: None))
    session.url = "http://example.com"
    # Should not hang, should call debug for status and cover else branch
    spider.spider(session)
    assert debug.called


def test_start_scan_fallback(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 404 (no sitemap)
    res = mock.Mock(status_code=404, text="not found")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    debug = mock.Mock()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should call debug for fallback
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)
    assert debug.called


def test_start_scan_no_urls(monkeypatch):
    session = DummySession()
    # Simulate sitemap.xml returns 200 with <urlset> but no <loc> tags, triggers else branch
    res = mock.Mock(status_code=200, text="<urlset><url><foo>bar</foo></url></urlset>")
    monkeypatch.setattr(spider.network, "http_get", lambda url, allow: res)
    debug = mock.Mock()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=lambda: None)
    )
    monkeypatch.setattr(spider, "Pool", lambda n: pool)
    mgr = mock.Mock(Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: []))
    monkeypatch.setattr(spider, "Manager", lambda: mgr)
    # Should not raise, should call debug for no URLs found
    spider._start_scan(session, session.url, [session.url], mock.Mock(), pool)
    assert debug.called


def test_get_links_exception_debug(monkeypatch):
    session = DummySession()
    pool = mock.Mock(apply_async=lambda *a, **k: mock.Mock())
    monkeypatch.setattr(spider, "_links", [])
    monkeypatch.setattr(spider, "_insecure", [])
    monkeypatch.setattr(spider, "_tasks", [])
    monkeypatch.setattr(spider, "_lock", mock.Mock())
    debug_exception = mock.Mock()
    debug = mock.Mock()
    monkeypatch.setattr(
        spider, "output", mock.Mock(debug=debug, debug_exception=debug_exception)
    )

    # Simulate exception in for url in urls
    def raise_exc(url, allow):
        raise Exception("fail")

    monkeypatch.setattr(spider.network, "http_get", raise_exc)
    queue = mock.Mock(put=lambda x: None)
    # Should not raise, should call debug_exception and debug at end
    spider._get_links(session, session.url, [session.url], queue, pool)
    assert debug_exception.called
    assert debug.called


from unittest.mock import MagicMock, patch

import pytest

from yawast.scanner.modules.http import spider
from yawast.scanner.session import Session


class DummySession:
    url = "http://test.local/"
    args = type("Args", (), {"php_page": None})()


@pytest.fixture
def reset_spider_globals():
    spider._links = []
    spider._insecure = []
    spider._tasks = []
    yield
    spider._links = []
    spider._insecure = []
    spider._tasks = []


def test_spider_no_sitemap_recurses(reset_spider_globals):
    # Simulate a site with 3 pages linked together
    html_map = {
        "http://test.local/": '<a href="/a">A</a>',
        "http://test.local/a": '<a href="/b">B</a>',
        "http://test.local/b": "",
    }

    def fake_http_get(url, allow_redirects=True):
        class DummyRes:
            def __init__(self, url):
                self.url = url
                self.status_code = (
                    200 if url != "http://test.local/sitemap.xml" else 404
                )
                self.text = html_map.get(url, "")
                self.headers = {}

        return DummyRes(url)

    with patch(
        "yawast.scanner.modules.http.spider.network.http_get", side_effect=fake_http_get
    ):
        with patch(
            "yawast.scanner.modules.http.spider.network.response_body_is_text",
            return_value=True,
        ):
            with patch(
                "yawast.scanner.modules.http.spider.response_scanner.check_response",
                return_value=[],
            ):
                session = DummySession()
                links, results = spider.spider(session)
                assert set(links) == {"http://test.local/a", "http://test.local/b"}
                assert results == []


def test_spider_with_sitemap_skips_recursion(reset_spider_globals):
    # Simulate a site with a sitemap.xml
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>http://test.local/a</loc></url>
        <url><loc>http://test.local/b</loc></url>
    </urlset>"""
    html_map = {
        "http://test.local/": "",
        "http://test.local/a": "",
        "http://test.local/b": "",
        "http://test.local/sitemap.xml": sitemap_xml,
    }

    def fake_http_get(url, allow_redirects=True):
        class DummyRes:
            def __init__(self, url):
                self.url = url
                self.status_code = (
                    200 if url == "http://test.local/sitemap.xml" else 200
                )
                self.text = html_map.get(url, "")
                self.headers = {}

        return DummyRes(url)

    with patch(
        "yawast.scanner.modules.http.spider.network.http_get", side_effect=fake_http_get
    ):
        with patch(
            "yawast.scanner.modules.http.spider.network.response_body_is_text",
            return_value=True,
        ):
            with patch(
                "yawast.scanner.modules.http.spider.response_scanner.check_response",
                return_value=[],
            ):
                session = DummySession()
                links, results = spider.spider(session)
                assert set(links) == {"http://test.local/a", "http://test.local/b"}
                assert results == []
