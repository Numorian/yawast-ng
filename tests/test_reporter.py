import gc
import json
import os
import tempfile
import types
import zipfile
from unittest import mock
from unittest.mock import MagicMock, call, patch

import pytest

from tests import utils
from yawast import config
from yawast.reporting import reporter
from yawast.reporting.enums import Severity, Vulnerabilities, VulnerabilityInfo
from yawast.reporting.evidence import Evidence
from yawast.reporting.issue import Issue
from yawast.reporting.result import Result


class TestReporterInit:
    def teardown_method(self):
        # Reset the global variable after each test
        reporter._output_file = ""

    @patch("os.path.abspath", side_effect=lambda x: f"/abs/{x}")
    def test_init_none(self, mock_abspath):
        reporter.init(None)
        assert reporter._output_file == ""

    @patch("time.time", return_value=123)
    @patch("os.path.isdir", return_value=True)
    @patch("os.path.abspath", side_effect=lambda x: f"/abs/{x}")
    def test_init_directory(self, mock_abspath, mock_isdir, mock_time):
        reporter.init("test_dir")
        assert "yawast_123.json" in reporter._output_file
        assert reporter._output_file.startswith("/abs/test_dir/")

    @patch("os.path.isfile", return_value=False)
    @patch("os.path.isdir", return_value=False)
    @patch("os.path.abspath", side_effect=lambda x: f"/abs/{x}")
    def test_init_file(self, mock_abspath, mock_isdir, mock_isfile):
        reporter.init("test_output.json")
        assert reporter._output_file == "/abs/test_output.json"


class TestReporterSaveOutput:
    def setup_method(self):
        # Save original references
        self.orig_issues = reporter._issues
        self.orig_info = reporter._info
        self.orig_data = reporter._data
        self.orig_output_file = reporter._output_file
        # Mock data
        reporter._issues = {"example.com": {}}
        reporter._issues["example.com"][Vulnerabilities.SERVER_INVALID_404_FILE] = {
            Result.from_evidence(
                Evidence("https://example.com", "<request>", "<response>"),
                "test",
                "test",
            )
        }
        reporter._info = {}
        reporter._data = {}
        reporter._output_file = "/tmp/test_output"
        # Ensure config is reset for each test
        config.no_json_compression = False

    def teardown_method(self):
        # Restore original references
        reporter._issues = self.orig_issues
        reporter._info = self.orig_info
        reporter._data = self.orig_data
        reporter._output_file = self.orig_output_file
        config.no_json_compression = False

    @patch("zipfile.ZipFile")
    @patch("os.path.isfile", return_value=False)
    def test_save_output_no_spinner(self, mock_isfile, mock_zip):
        config.no_json_compression = False  # Force compression for this test
        with utils.capture_sys_output() as (stdout, stderr):
            reporter.save_output()
        mock_zip.assert_called_once_with("/tmp/test_output.zip", "x", zipfile.ZIP_BZIP2)

    @patch("zipfile.ZipFile")
    @patch("os.path.isfile", return_value=True)
    @patch("time.time", return_value=123456)
    def test_save_output_existing_zip(self, mock_time, mock_isfile, mock_zip):
        config.no_json_compression = False  # Force compression for this test
        with utils.capture_sys_output() as (stdout, stderr):
            reporter.save_output()
        # Ensure filename changed due to existing zip
        expected_path = "/tmp/test_output_123456.json.zip"
        mock_zip.assert_called_once_with(expected_path, "x", zipfile.ZIP_BZIP2)

    @patch("zipfile.ZipFile")
    @patch("os.path.isfile", return_value=False)
    def test_save_output_with_spinner(self, mock_isfile, mock_zip):
        config.no_json_compression = False  # Force compression for this test
        spinner_mock = MagicMock()
        with utils.capture_sys_output() as (stdout, stderr):
            reporter.save_output(spinner_mock)
        spinner_mock.stop.assert_called()
        spinner_mock.start.assert_called()
        mock_zip.assert_called_once()

    def test_save_output_no_compression(self, tmp_path, monkeypatch):
        reporter._output_file = str(tmp_path / "out.json")
        reporter.setup("example.com")
        issue = make_issue()
        reporter.register(issue)
        monkeypatch.setattr(reporter.output, "debug", lambda x: None)
        monkeypatch.setattr(reporter.output, "info", lambda x: None)
        monkeypatch.setattr(reporter.output, "warn", lambda x: None)
        monkeypatch.setattr(reporter.output, "vuln", lambda x: None)
        monkeypatch.setattr(reporter.output, "print_color", lambda *a, **k: None)
        monkeypatch.setattr(
            reporter,
            "ExecutionTimer",
            lambda: mock.MagicMock(
                __enter__=lambda s: s, __exit__=lambda s, e, v, t: None, to_ms=lambda: 1
            ),
        )
        # Set config to disable compression
        monkeypatch.setattr(reporter.config, "no_json_compression", True)
        reporter.save_output()
        assert os.path.exists(str(tmp_path / "out.json"))
        # Should not create a .zip file
        assert not os.path.exists(str(tmp_path / "out.json.zip"))


class TestReporterGetOutputFile:
    def teardown_method(self):
        reporter._output_file = ""

    def test_get_output_file_with_value(self):
        reporter._output_file = "/some/path/test_output"
        assert reporter.get_output_file() == "/some/path/test_output.zip"

    def test_get_output_file_empty(self):
        reporter._output_file = ""
        assert reporter.get_output_file() == ""


class TestReporterSetup:
    def setup_method(self):
        self.orig_domain = reporter._domain
        self.orig_issues = reporter._issues
        self.orig_data = reporter._data
        reporter._domain = ""
        reporter._issues = {}
        reporter._data = {}

    def teardown_method(self):
        reporter._domain = self.orig_domain
        reporter._issues = self.orig_issues
        reporter._data = self.orig_data

    def test_setup_creates_new_domain_keys(self):
        domain = "example.com"
        reporter.setup(domain)
        assert reporter._domain == domain
        assert domain in reporter._issues
        assert domain in reporter._data
        assert reporter._issues[domain] == {}
        assert reporter._data[domain] == {}

    def test_setup_preserves_existing_domain_data(self):
        domain = "example.com"
        reporter._issues[domain] = {"test_key": "test_value"}
        reporter._data[domain] = {"test_key": "test_value"}
        reporter.setup(domain)
        assert reporter._issues[domain] == {"test_key": "test_value"}
        assert reporter._data[domain] == {"test_key": "test_value"}


class TestReporterIsRegistered:
    def setup_method(self):
        self.orig_issues = reporter._issues
        self.orig_domain = reporter._domain
        reporter._issues = {}
        reporter._domain = ""

    def teardown_method(self):
        reporter._issues = self.orig_issues
        reporter._domain = self.orig_domain

    def test_is_registered_no_issues(self):
        assert not reporter.is_registered(Vulnerabilities.SERVER_INVALID_404_FILE)

    def test_is_registered_different_domain(self):
        reporter._issues["example.com"] = {}
        reporter._domain = "test.com"
        assert not reporter.is_registered(Vulnerabilities.SERVER_INVALID_404_FILE)

    def test_is_registered_with_vuln(self):
        reporter._domain = "example.com"
        reporter._issues["example.com"] = {
            Vulnerabilities.SERVER_INVALID_404_FILE: ["sample_issue"]
        }
        assert reporter.is_registered(Vulnerabilities.SERVER_INVALID_404_FILE)

    def test_is_registered_domain_not_present_in_issues(self):
        reporter._domain = "not_in_issues"
        assert not reporter.is_registered(Vulnerabilities.SERVER_INVALID_404_FILE)

    def test_is_registered_issue_not_present(self):
        reporter._domain = "example.com"
        reporter._issues["example.com"] = {}
        assert not reporter.is_registered(Vulnerabilities.SERVER_INVALID_404_FILE)


class TestReporterRegisterData:
    def setup_method(self):
        self.orig_data = reporter._data
        self.orig_output_file = reporter._output_file
        self.orig_domain = reporter._domain
        reporter._data = {}
        reporter._output_file = "/tmp/test_output"
        reporter._domain = "example.com"

    def teardown_method(self):
        reporter._data = self.orig_data
        reporter._output_file = self.orig_output_file
        reporter._domain = self.orig_domain

    def test_register_data_with_existing_domain(self):
        reporter._data["example.com"] = {"existing_key": "existing_value"}
        reporter.register_data("new_key", "new_value")
        assert "new_key" in reporter._data["example.com"]
        assert reporter._data["example.com"]["new_key"] == "new_value"
        assert "existing_key" in reporter._data["example.com"]

    def test_register_data_with_new_domain(self):
        reporter._domain = "newdomain.com"
        reporter.register_data("new_key", "new_value")
        assert "newdomain.com" in reporter._data
        assert "new_key" in reporter._data["newdomain.com"]
        assert reporter._data["newdomain.com"]["new_key"] == "new_value"

    def test_register_data_with_no_domain(self):
        reporter._domain = None
        reporter.register_data("global_key", "global_value")
        assert "global_key" in reporter._data
        assert reporter._data["global_key"] == "global_value"

    def test_register_data_appends_to_existing_list(self):
        reporter._data["example.com"] = {"list_key": [1, 2, 3]}
        reporter.register_data("list_key", [4, 5])
        assert reporter._data["example.com"]["list_key"] == [1, 2, 3, 4, 5]

    def test_register_data_updates_existing_dict(self):
        reporter._data["example.com"] = {"dict_key": {"a": 1}}
        reporter.register_data("dict_key", {"b": 2})
        assert reporter._data["example.com"]["dict_key"] == {"a": 1, "b": 2}

    def test_register_data_overwrites_non_matching_types(self):
        reporter._data["example.com"] = {"key": [1, 2, 3]}
        reporter.register_data("key", {"a": 1})
        assert reporter._data["example.com"]["key"] == {"a": 1}


class TestReporterRegisterMessage:
    def setup_method(self):
        self.orig_info = reporter._info
        self.orig_output_file = reporter._output_file
        self.orig_config = config.include_debug_in_output
        reporter._info = {}
        reporter._output_file = "/tmp/test_output"
        config.include_debug_in_output = True

    def teardown_method(self):
        reporter._info = self.orig_info
        reporter._output_file = self.orig_output_file
        config.include_debug_in_output = self.orig_config

    def test_register_message_creates_messages_key(self):
        reporter.register_message("Test message", "info")
        assert "messages" in reporter._info
        assert "info" in reporter._info["messages"]
        assert len(reporter._info["messages"]["info"]) == 1
        assert "Test message" in reporter._info["messages"]["info"][0]

    def test_register_message_appends_to_existing_kind(self):
        reporter._info["messages"] = {"info": ["[2023-01-01 UTC]: Existing message"]}
        reporter.register_message("New message", "info")
        assert len(reporter._info["messages"]["info"]) == 2
        assert "New message" in reporter._info["messages"]["info"][1]

    def test_register_message_creates_new_kind(self):
        reporter.register_message("Test message", "warning")
        assert "warning" in reporter._info["messages"]
        assert len(reporter._info["messages"]["warning"]) == 1
        assert "Test message" in reporter._info["messages"]["warning"][0]

    def test_register_message_ignores_debug_when_disabled(self):
        config.include_debug_in_output = False
        reporter.register_message("Debug message", "debug")
        assert len(reporter._info["messages"]["debug"]) == 0

    def test_register_message_logs_debug_when_enabled(self):
        config.include_debug_in_output = True
        reporter.register_message("Debug message", "debug")
        assert "debug" in reporter._info["messages"]
        assert len(reporter._info["messages"]["debug"]) == 1
        assert "Debug message" in reporter._info["messages"]["debug"][0]

    def test_register_message_no_output_file(self):
        reporter._output_file = ""
        reporter.register_message("Test message", "info")
        assert "messages" not in reporter._info


class TestReporterRegister:
    def setup_method(self):
        self.orig_issues = reporter._issues
        self.orig_domain = reporter._domain
        self.orig_output_file = reporter._output_file
        reporter._issues = {}
        reporter._domain = "example.com"
        reporter._output_file = ""

    def teardown_method(self):
        reporter._issues = self.orig_issues
        reporter._domain = self.orig_domain
        reporter._output_file = self.orig_output_file

    def test_register_creates_new_vulnerability_list(self):
        issue = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request>", "<response>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        assert (
            Vulnerabilities.SERVER_INVALID_404_FILE in reporter._issues["example.com"]
        )
        assert (
            len(
                reporter._issues["example.com"][Vulnerabilities.SERVER_INVALID_404_FILE]
            )
            == 1
        )
        assert (
            reporter._issues["example.com"][Vulnerabilities.SERVER_INVALID_404_FILE][0]
            == issue
        )

    def test_register_does_not_duplicate_issues(self):
        issue = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request>", "<response>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        reporter.register(issue)  # Register the same issue again
        assert (
            len(
                reporter._issues["example.com"][Vulnerabilities.SERVER_INVALID_404_FILE]
            )
            == 1
        )

    def test_register_handles_different_issues(self):
        issue1 = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request1>", "<response1>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        issue2 = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request2>", "<response2>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue1)
        reporter.register(issue2)
        assert (
            len(
                reporter._issues["example.com"][Vulnerabilities.SERVER_INVALID_404_FILE]
            )
            == 2
        )

    @patch("yawast.reporting.reporter.output.debug")
    def test_register_logs_duplicate_issue(self, mock_debug):
        issue = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request>", "<response>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        reporter.register(issue)  # Register the same issue again
        mock_debug.assert_called_with(
            f"Duplicate Issue: {issue.id} (duplicate of {issue.id})"
        )

    def test_register_removes_evidence_when_no_output_file(self):
        issue = Issue(
            url="https://example.com",
            evidence={"request": "<request>", "response": "<response>"},
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        registered_issue = reporter._issues["example.com"][
            Vulnerabilities.SERVER_INVALID_404_FILE
        ][0]
        assert registered_issue.evidence["request"] == ""
        assert registered_issue.evidence["response"] == ""

    @patch("yawast.reporting.evidence.Evidence.cache_to_file")
    def test_register_caches_evidence_to_disk(self, mock_cache_to_file):
        reporter._output_file = "/tmp/test_output"
        issue = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request>", "<response>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        mock_cache_to_file.assert_called_once()

    @patch("yawast.reporting.reporter.output.debug")
    @patch(
        "yawast.reporting.evidence.Evidence.cache_to_file",
        side_effect=Exception("Cache error"),
    )
    def test_register_logs_cache_error(self, mock_cache_to_file, mock_debug):
        reporter._output_file = "/tmp/test_output"
        issue = Issue(
            url="https://example.com",
            evidence=Evidence("https://example.com", "<request>", "<response>"),
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.register(issue)
        mock_debug.assert_called_with("Error caching evidence: Cache error")


class TestReporterDisplay:
    def setup_method(self):
        self.orig_issues = reporter._issues
        self.orig_domain = reporter._domain
        self.orig_output_file = reporter._output_file
        reporter._issues = {}
        reporter._domain = "example.com"
        reporter._output_file = ""

    def teardown_method(self):
        reporter._issues = self.orig_issues
        reporter._domain = self.orig_domain
        reporter._output_file = self.orig_output_file

    @patch("yawast.reporting.reporter.output.vuln")
    @patch("yawast.reporting.reporter.register")
    def test_display_critical_severity(self, mock_register, mock_vuln):
        issue = Issue(
            url="https://example.com",
            evidence=None,
            vuln=Vulnerabilities.TLS_HEARTBLEED,
        )
        reporter.display("Critical issue message", issue)
        mock_vuln.assert_called_once_with("Critical issue message")
        mock_register.assert_called_once_with(issue)
        assert issue.evidence == "Critical issue message"

    @patch("yawast.reporting.reporter.output.warn")
    @patch("yawast.reporting.reporter.register")
    def test_display_medium_severity(self, mock_register, mock_warn):
        issue = Issue(
            url="https://example.com",
            evidence=None,
            vuln=Vulnerabilities.TLS_GOLDENDOODLE_NE,
        )
        reporter.display("Medium issue message", issue)
        mock_warn.assert_called_once_with("Medium issue message")
        mock_register.assert_called_once_with(issue)
        assert issue.evidence == "Medium issue message"

    @patch("yawast.reporting.reporter.output.info")
    @patch("yawast.reporting.reporter.register")
    def test_display_low_severity(self, mock_register, mock_info):
        issue = Issue(
            url="https://example.com",
            evidence=None,
            vuln=Vulnerabilities.TLS_LIMITED_FORWARD_SECRECY,
        )
        reporter.display("Low issue message", issue)
        mock_info.assert_called_once_with("Low issue message")
        mock_register.assert_called_once_with(issue)
        assert issue.evidence == "Low issue message"

    @patch("yawast.reporting.reporter.output.info")
    @patch("yawast.reporting.reporter.register")
    def test_display_with_existing_evidence(self, mock_register, mock_info):
        issue = Issue(
            url="https://example.com",
            evidence="Existing evidence",
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.display("Low issue message", issue)
        mock_info.assert_called_once_with("Low issue message")
        mock_register.assert_called_once_with(issue)
        assert issue.evidence == "Existing evidence"

    @patch("yawast.reporting.reporter.output.vuln")
    @patch("yawast.reporting.reporter.is_registered", return_value=False)
    @patch("yawast.reporting.reporter.register")
    def test_display_not_registered(self, mock_register, mock_is_registered, mock_vuln):
        issue = Issue(
            url="https://example.com",
            evidence=None,
            vuln=Vulnerabilities.TLS_HEARTBLEED,
        )
        reporter.display("Critical issue message", issue)
        mock_vuln.assert_called_once_with("Critical issue message")
        mock_register.assert_called_once_with(issue)

    @patch("yawast.reporting.reporter.output.info")
    @patch("yawast.reporting.reporter.is_registered", return_value=True)
    @patch("yawast.reporting.reporter.register")
    def test_display_registered(self, mock_register, mock_is_registered, mock_info):
        issue = Issue(
            url="https://example.com",
            evidence=None,
            vuln=Vulnerabilities.SERVER_INVALID_404_FILE,
        )
        reporter.display("Low issue message", issue)
        mock_info.assert_not_called()
        mock_register.assert_called_once_with(issue)
        mock_is_registered.assert_called_once_with(issue.vulnerability)


class TestReporterDisplayResults:
    @patch("yawast.reporting.reporter.display")
    @patch("yawast.reporting.issue.Issue.from_result")
    def test_display_results_calls_display(self, mock_from_result, mock_display):
        # Mock Result and Issue objects
        mock_result = MagicMock()
        mock_result.message = "Test message"
        mock_issue = MagicMock()
        mock_from_result.return_value = mock_issue

        # Call the function
        reporter.display_results([mock_result], padding="  ")

        # Verify that Issue.from_result was called with the correct argument
        mock_from_result.assert_called_once_with(mock_result)

        # Verify that display was called with the correct arguments
        mock_display.assert_called_once_with("  Test message", mock_issue)

    @patch("yawast.reporting.reporter.display")
    @patch("yawast.reporting.issue.Issue.from_result")
    def test_display_results_multiple_results(self, mock_from_result, mock_display):
        # Mock multiple Result and Issue objects
        mock_results = [MagicMock(message=f"Message {i}") for i in range(3)]
        mock_issues = [MagicMock() for _ in range(3)]
        mock_from_result.side_effect = mock_issues

        # Call the function
        reporter.display_results(mock_results, padding=">> ")

        # Verify that Issue.from_result was called for each result
        assert mock_from_result.call_count == 3
        mock_from_result.assert_has_calls([call(res) for res in mock_results])

        # Verify that display was called for each result
        assert mock_display.call_count == 3
        mock_display.assert_has_calls(
            [
                call(f">> {res.message}", issue)
                for res, issue in zip(mock_results, mock_issues)
            ]
        )

    @patch("yawast.reporting.reporter.display")
    @patch("yawast.reporting.issue.Issue.from_result")
    def test_display_results_no_padding(self, mock_from_result, mock_display):
        # Mock Result and Issue objects
        mock_result = MagicMock()
        mock_result.message = "Test message"
        mock_issue = MagicMock()
        mock_from_result.return_value = mock_issue

        # Call the function without padding
        reporter.display_results([mock_result])

        # Verify that display was called with no padding
        mock_display.assert_called_once_with("Test message", mock_issue)

    @patch("yawast.reporting.reporter.display")
    @patch("yawast.reporting.issue.Issue.from_result")
    def test_display_results_empty_results(self, mock_from_result, mock_display):
        # Call the function with an empty list
        reporter.display_results([])

        # Verify that neither Issue.from_result nor display was called
        mock_from_result.assert_not_called()
        mock_display.assert_not_called()


def setup_module(module):
    # Reset reporter state before each test module
    reporter._issues.clear()
    reporter._info.clear()
    reporter._data.clear()
    reporter._domain = ""
    reporter._output_file = ""
    reporter._injection_points.clear()


def make_issue():
    vuln = Vulnerabilities.get("App_WordPress_Version")
    ev = Evidence("http://foo", "req", "resp")
    return Issue(vuln, "http://foo", ev)


def test_init_and_get_output_file(tmp_path):
    out_file = tmp_path / "out.json"
    reporter.init(str(out_file))
    assert reporter.get_output_file().endswith("out.json.zip")


def test_setup_and_register():
    reporter._output_file = "foo.json"
    reporter.setup("example.com")
    issue = make_issue()
    reporter.register(issue)
    assert reporter.is_registered(issue.vulnerability)


def test_register_duplicate(monkeypatch):
    reporter._output_file = "foo.json"
    reporter.setup("example.com")
    issue = make_issue()
    reporter.register(issue)
    with mock.patch("yawast.shared.output.debug") as debug:
        reporter.register(issue)
        debug.assert_called()


def test_register_info_and_data():
    reporter._output_file = "foo.json"
    reporter.setup("example.com")
    reporter.register_info("foo", 123)
    assert reporter._info["foo"] == 123
    reporter.register_data("bar", {"baz": 1})
    assert "bar" in reporter._data["example.com"]


def test_register_message(monkeypatch):
    reporter._output_file = "foo.json"
    monkeypatch.setattr(reporter.config, "include_debug_in_output", True)
    reporter.register_message("msg", "debug")
    assert "debug" in reporter._info["messages"]


def test_register_injection_points():
    reporter._output_file = "foo.json"
    reporter.setup("example.com")
    point = mock.Mock(spec=reporter.InjectionPoint)
    reporter.register_injection_points([point])
    assert point in reporter._injection_points["example.com"]


def test_display_and_display_results(monkeypatch):
    reporter._output_file = "foo.json"
    reporter.setup("example.com")
    issue = make_issue()
    monkeypatch.setattr(reporter.output, "vuln", lambda x: None)
    monkeypatch.setattr(reporter.output, "warn", lambda x: None)
    monkeypatch.setattr(reporter.output, "info", lambda x: None)
    reporter.display("msg", issue)
    res = types.SimpleNamespace(
        message="msg",
        vulnerability=issue.vulnerability,
        url="http://foo",
        evidence=issue.evidence,
    )
    monkeypatch.setattr(reporter, "Issue", Issue)
    reporter.display_results([res])


def test_save_output(tmp_path, monkeypatch):
    monkeypatch.setattr(reporter.config, "no_json_compression", False)
    reporter._output_file = str(tmp_path / "out.json")
    reporter.setup("example.com")
    issue = make_issue()
    reporter.register(issue)
    monkeypatch.setattr(
        reporter,
        "ExecutionTimer",
        lambda: mock.MagicMock(
            __enter__=lambda s: s, __exit__=lambda s, e, v, t: None, to_ms=lambda: 1
        ),
    )
    monkeypatch.setattr(reporter.output, "debug", lambda x: None)
    monkeypatch.setattr(reporter.output, "info", lambda x: None)
    monkeypatch.setattr(reporter.output, "warn", lambda x: None)
    monkeypatch.setattr(reporter.output, "vuln", lambda x: None)
    monkeypatch.setattr(reporter.output, "print_color", lambda *a, **k: None)
    reporter.save_output()
    assert os.path.exists(str(tmp_path / "out.json.zip"))


def test__register_data_and__convert_keys():
    d = {"foo": [1]}
    reporter._register_data(d, "foo", [2, 3])
    assert d["foo"] == [1, 2, 3]
    d2 = {"bar": {"baz": 1}}
    reporter._register_data(d2, "bar", {"baz": 2})
    assert d2["bar"]["baz"] == 2
    d3 = {"x": 1}
    out = reporter._convert_keys(d3)
    assert out["x"] == 1
