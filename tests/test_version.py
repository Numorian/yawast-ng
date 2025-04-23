import os
import types
from unittest import mock

import pytest

from yawast import _version


def test_version_is_from_git_true(tmp_path):
    version_file = tmp_path / "_static_version.py"
    version_file.write_text("version = '__use_git__'\n")
    with mock.patch.object(_version, "package_root", str(tmp_path)):
        assert _version.version_is_from_git(str(version_file.name))


def test_version_is_from_git_false(tmp_path):
    version_file = tmp_path / "_static_version.py"
    version_file.write_text("version = '1.2.3'\n")
    with mock.patch.object(_version, "package_root", str(tmp_path)):
        assert not _version.version_is_from_git(str(version_file.name))


def test_pep440_format():
    v = _version.Version("1.2.3", None, None)
    assert _version.pep440_format(v) == "1.2.3"
    v = _version.Version("1.2.3", "4", None)
    assert _version.pep440_format(v) == "1.2.3.dev4"
    v = _version.Version("1.2.3-dev", "4", None)
    assert _version.pep440_format(v) == "1.2.3-dev4"
    v = _version.Version("1.2.3", None, ["g123", "dirty"])
    assert _version.pep440_format(v) == "1.2.3+g123.dirty"


def test_get_version_static(monkeypatch, tmp_path):
    version_file = tmp_path / "_static_version.py"
    version_file.write_text("version = '2.0.0'\n")
    monkeypatch.setattr(_version, "package_root", str(tmp_path))
    assert _version.get_version(str(version_file.name)) == "2.0.0"


def test_get_version_git(monkeypatch):
    monkeypatch.setattr(
        _version, "get_static_version_info", lambda v: {"version": "__use_git__"}
    )
    monkeypatch.setattr(
        _version,
        "get_version_from_git",
        lambda: _version.Version("1.0.0", "1", ["g123"]),
    )
    monkeypatch.setattr(_version, "pep440_format", lambda v: "1.0.0.dev1+g123")
    assert _version.get_version("irrelevant") == "1.0.0.dev1+g123"


def test_get_version_git_archive(monkeypatch):
    monkeypatch.setattr(
        _version, "get_static_version_info", lambda v: {"version": "__use_git__"}
    )
    monkeypatch.setattr(_version, "get_version_from_git", lambda: None)
    monkeypatch.setattr(
        _version,
        "get_version_from_git_archive",
        lambda v: _version.Version("1.0.0", None, None),
    )
    monkeypatch.setattr(_version, "pep440_format", lambda v: "1.0.0")
    assert _version.get_version("irrelevant") == "1.0.0"


def test_get_version_git_fallback(monkeypatch):
    monkeypatch.setattr(
        _version, "get_static_version_info", lambda v: {"version": "__use_git__"}
    )
    monkeypatch.setattr(_version, "get_version_from_git", lambda: None)
    monkeypatch.setattr(_version, "get_version_from_git_archive", lambda v: None)
    monkeypatch.setattr(_version, "pep440_format", lambda v: "0.0.0")
    assert _version.get_version("irrelevant") == "0.0.0"


def test_get_version_from_git_archive_tag():
    info = {"refnames": "tag: v2.1.0", "git_hash": "abc123"}
    v = _version.get_version_from_git_archive(info)
    assert v.release == "2.1.0"
    assert v.dev is None
    assert v.labels is None


def test_get_version_from_git_archive_hash():
    info = {"refnames": "", "git_hash": "abc123"}
    v = _version.get_version_from_git_archive(info)
    assert v.release == "0.0.0"
    assert v.labels == ["gabc123"]


def test_get_version_from_git_archive_unexpanded():
    info = {"refnames": "$Format:%D$", "git_hash": "$Format:%h$"}
    assert _version.get_version_from_git_archive(info) is None


def test_get_version_from_git_archive_missing_keys():
    info = {}
    assert _version.get_version_from_git_archive(info) is None


def test_write_version(tmp_path):
    fname = tmp_path / "ver.py"
    with mock.patch.object(_version, "__version__", "1.2.3"):
        _version._write_version(str(fname))
    content = fname.read_text()
    assert "version = '1.2.3'" in content
