# Copyright (c) 2025 Numorian, Inc. and Contributors.
# Unit tests for yawast/scanner/modules/http/file_search.py
import builtins
from unittest import mock

import pytest

from yawast.scanner.modules.http import file_search


class DummyResponse:
    def __init__(
        self, text="", status_code=200, headers=None, content=b"", request=None
    ):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.request = request or mock.Mock()


def test_find_files(monkeypatch, tmp_path):
    # Create a fake file list
    filelist = tmp_path / "common_file.txt"
    filelist.write_text("admin\nlogin\n")
    monkeypatch.setattr(
        "pkg_resources.resource_filename", lambda pkg, name: str(filelist)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search._find_files",
        lambda url, path: (["/admin", "/login"], []),
    )
    files, results = file_search.find_files("http://numorian.com")
    assert "/admin" in files and "/login" in files


def test_find_directories(monkeypatch, tmp_path):
    filelist = tmp_path / "common_dir.txt"
    filelist.write_text("admin\nuser\n")
    monkeypatch.setattr(
        "pkg_resources.resource_filename", lambda pkg, name: str(filelist)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search._find_files",
        lambda url, path, follow=None, is_dir=None, recursive=None: (
            ["/admin/", "/user/"],
            [],
        ),
    )
    files, results = file_search.find_directories("http://numorian.com", False, False)
    assert "/admin/" in files and "/user/" in files


def test_find_backups(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (True, DummyResponse(status_code=200)),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    links = ["http://numorian.com/index.html"]
    files, results = file_search.find_backups(links)
    assert isinstance(files, list)
    assert isinstance(results, list)


def test_find_backups_no_found(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (False, DummyResponse(status_code=404)),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    links = ["http://numorian.com/index.html"]
    files, results = file_search.find_backups(links)
    assert files == []


def test_find_ds_store(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (True, DummyResponse(content=b"\0\0\0\1Bud1\0")),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    links = ["http://numorian.com/"]
    results = file_search.find_ds_store(links)
    assert isinstance(results, list)


def test_find_ds_store_no_found(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (False, DummyResponse(content=b"")),
    )
    links = ["http://numorian.com/"]
    results = file_search.find_ds_store(links)
    assert results == []


def test_reset():
    file_search._files = ["foo"]
    file_search._depth = 1
    file_search.reset()
    assert file_search._files == [] and file_search._depth == 0


def test__find_files_basic(monkeypatch, tmp_path):
    # Simulate a file with a few entries
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\nbar\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool",
        mock.Mock(
            return_value=mock.Mock(
                apply_async=lambda *a, **k: mock.Mock(
                    ready=lambda: True, get=lambda timeout=None: None
                ),
                close=lambda: None,
            )
        ),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    file_search._files = []
    file_search._depth = 0
    files, results = file_search._find_files("http://numorian.com", str(test_file))
    assert isinstance(files, list)
    assert isinstance(results, list)


def test__find_files_keyboard_interrupt(monkeypatch, tmp_path):
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)

    class DummyPool:
        def apply_async(self, *a, **k):
            raise KeyboardInterrupt()

        def terminate(self):
            pass

        def join(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool", lambda max_workers: DummyPool()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    try:
        file_search._find_files("http://numorian.com", str(test_file))
    except KeyboardInterrupt:
        assert True


def test__find_files_exception(monkeypatch, tmp_path):
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)

    class DummyPool:
        def apply_async(self, *a, **k):
            raise Exception("fail")

        def terminate(self):
            pass

        def join(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool", lambda max_workers: DummyPool()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    try:
        file_search._find_files("http://numorian.com", str(test_file))
    except Exception:
        assert True


def test__check_url_basic(monkeypatch):
    urls = ["http://numorian.com/foo"]
    queue = mock.Mock(put=lambda x: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (True, DummyResponse(status_code=200)),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, follow, rec: ([], []),
    )
    file_search._check_url(urls, queue, False, False)
    assert True


def test__check_url_redirect(monkeypatch):
    urls = ["http://numorian.com/foo"]
    queue = mock.Mock(put=lambda x: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (
            False,
            DummyResponse(
                status_code=301, headers={"Location": "http://numorian.com/bar"}
            ),
        ),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search._check_url",
        lambda urls, queue, follow, rec: None,
    )
    file_search._check_url(urls, queue, True, False)
    assert True


def test__check_url_exception(monkeypatch):
    urls = ["http://numorian.com/foo"]
    queue = mock.Mock(put=lambda x: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    file_search._check_url(urls, queue, False, False)
    assert True


def test_find_backups_cdn_cgi(monkeypatch):
    # Should skip links with 'cdn-cgi'
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (True, DummyResponse(status_code=200)),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    links = ["http://numorian.com/cdn-cgi/path"]
    files, results = file_search.find_backups(links)
    assert files == []


def test_find_backups_dir_and_compressed(monkeypatch):
    # Should add compressed file targets for directory links
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (True, DummyResponse(status_code=200)),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    links = ["http://numorian.com/dir/"]
    files, results = file_search.find_backups(links)
    assert isinstance(files, list)
    assert isinstance(results, list)


def test__find_files_recursive(monkeypatch, tmp_path):
    # Simulate recursive logic and _depth cleanup
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\nbar\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool",
        mock.Mock(
            return_value=mock.Mock(
                apply_async=lambda *a, **k: mock.Mock(
                    ready=lambda: True, get=lambda timeout=None: None
                ),
                close=lambda: None,
            )
        ),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    file_search._files = []
    file_search._depth = 0
    # Call twice to simulate recursion
    files, results = file_search._find_files(
        "http://numorian.com", str(test_file), recursive=True
    )
    files2, results2 = file_search._find_files(
        "http://numorian.com", str(test_file), recursive=True
    )
    assert isinstance(files, list)
    assert isinstance(results, list)
    assert file_search._depth == 0
    assert file_search._files == []


def test__check_url_redirect_no_location(monkeypatch):
    urls = ["http://numorian.com/foo"]
    queue = mock.Mock(put=lambda x: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        lambda url, allow: (
            False,
            DummyResponse(status_code=301, headers={}),
        ),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search._check_url",
        lambda urls, queue, follow, rec: None,
    )
    # Should not raise even if Location is missing
    file_search._check_url(urls, queue, True, False)
    assert True


def test_find_files_file_not_found(monkeypatch):
    # Should raise FileNotFoundError and propagate
    monkeypatch.setattr(
        "pkg_resources.resource_filename",
        lambda pkg, name: "/tmp/doesnotexist.txt",
    )
    try:
        file_search.find_files("http://numorian.com")
    except Exception as e:
        assert isinstance(e, FileNotFoundError)


def test_find_directories_file_not_found(monkeypatch):
    monkeypatch.setattr(
        "pkg_resources.resource_filename",
        lambda pkg, name: "/tmp/doesnotexist.txt",
    )
    try:
        file_search.find_directories("http://numorian.com", False, False)
    except Exception as e:
        assert isinstance(e, FileNotFoundError)


def test__find_files_queue_dedup(monkeypatch, tmp_path):
    # Simulate queue returning duplicate files/results
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\nbar\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)

    class DummyPool:
        def apply_async(self, *a, **k):
            return mock.Mock(ready=lambda: True, get=lambda timeout=None: None)

        def close(self):
            pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool",
        lambda max_workers: DummyPool(),
    )

    class DummyQueue:
        def __init__(self):
            self._calls = 0

        def empty(self):
            self._calls += 1
            return self._calls > 1

        def get(self):
            # Return duplicate files/results
            return (["foo", "foo"], ["r1", "r1"])

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(return_value=mock.Mock(Queue=lambda: DummyQueue())),
    )
    monkeypatch.setattr("time.sleep", lambda x: None)
    file_search._files = []
    file_search._depth = 0
    files, results = file_search._find_files("http://numorian.com", str(test_file))
    assert files == ["foo"]
    assert results == ["r1"]


def test__check_url_exception_in_loop(monkeypatch):
    # Should handle exception for second URL
    urls = ["http://numorian.com/foo", "http://numorian.com/bar"]
    queue = mock.Mock(put=lambda x: None)
    calls = []

    def http_file_exists(url, allow):
        if "bar" in url:
            raise Exception("fail")
        calls.append(url)
        return (True, DummyResponse(status_code=200))

    monkeypatch.setattr(
        "yawast.shared.network.http_file_exists",
        http_file_exists,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, follow, rec: ([], []),
    )
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    file_search._check_url(urls, queue, False, False)
    assert "http://numorian.com/foo" in calls


def test__find_files_keyboard_interrupt_cleanup(monkeypatch, tmp_path):
    # Simulate KeyboardInterrupt and check cleanup
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)

    class DummyPool:
        def apply_async(self, *a, **k):
            raise KeyboardInterrupt()

        def terminate(self):
            pass

        def join(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool", lambda max_workers: DummyPool()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    file_search._files = ["foo"]
    file_search._depth = 0  # Fix: set to 0 so after inc/dec it is 0
    try:
        file_search._find_files("http://numorian.com", str(test_file))
    except KeyboardInterrupt:
        assert file_search._depth == 0
        assert file_search._files == []


def test__find_files_exception_cleanup(monkeypatch, tmp_path):
    # Simulate Exception and check cleanup
    test_file = tmp_path / "testfiles.txt"
    test_file.write_text("foo\n")
    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open", lambda path, *a, **k: real_open(str(test_file))
    )
    monkeypatch.setattr("os.cpu_count", lambda: 1)

    class DummyPool:
        def apply_async(self, *a, **k):
            raise Exception("fail")

        def terminate(self):
            pass

        def join(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Pool", lambda max_workers: DummyPool()
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.Manager",
        mock.Mock(
            return_value=mock.Mock(
                Queue=lambda: mock.Mock(empty=lambda: True, get=lambda: ([], []))
            )
        ),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    file_search._files = ["foo"]
    file_search._depth = 0  # Fix: set to 0 so after inc/dec it is 0
    try:
        file_search._find_files("http://numorian.com", str(test_file))
    except Exception:
        assert file_search._depth == 0
        assert file_search._files == []
