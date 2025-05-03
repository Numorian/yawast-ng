import pytest

from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http import command_exec


class DummyResponse:
    def __init__(self, text):
        self.text = text


@pytest.fixture(autouse=True)
def patch_check_response(monkeypatch):
    monkeypatch.setattr(
        command_exec.response_scanner, "check_response", lambda *a, **kw: None
    )


@pytest.mark.parametrize(
    "payload,marker",
    [
        (";id", "uid=1000(guy) gid=1000(guy) groups=1000(guy)"),
        ("|cat /etc/passwd", "root:x:0:0:"),
        ("|type C:\\Windows\\win.ini", "[extensions]"),
        # Removed whoami as it's not a high-confidence marker
    ],
)
def test_command_exec_detected(monkeypatch, payload, marker):
    url = f"http://test/?q=foo"
    inj_point = InjectionPoint(url, "q", "GET", "foo")
    # Simulate the marker is NOT present in the original response
    orig_res = DummyResponse("no marker here")

    def fake_get(u):
        return DummyResponse(marker)

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, orig_res, inj_point, None)
    assert any(
        r.vulnerability == command_exec.Vulnerabilities.COMMAND_EXECUTION_CONFIRMED
        for r in results
    ), f"Command execution was not detected for marker: {marker}"


def test_command_exec_marker_already_present(monkeypatch):
    url = "http://test/?q=foo"
    inj_point = InjectionPoint(url, "q", "GET", "foo")
    marker = "root:x:0:0:"
    # Simulate the marker is present in the original response
    orig_res = DummyResponse(marker)

    def fake_get(u):
        return DummyResponse(marker)

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, orig_res, inj_point, None)
    assert (
        results == []
    ), "Should not report if marker is already present in original response"


def test_command_exec_not_detected(monkeypatch):
    url = "http://test/?q=foo"
    inj_point = InjectionPoint(url, "q", "GET", "foo")

    def fake_get(u):
        return DummyResponse("safe response")

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, None, inj_point, None)
    assert results == []


def test_command_exec_form_fields_preserved(monkeypatch):
    from bs4 import BeautifulSoup

    url = "http://test/?id=1"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    html = """
    <form action="#" method="GET">
        <input type="text" name="id" value="1">
        <input type="submit" name="Submit" value="Submit">
        <input type="hidden" name="hidden_field" value="foo">
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    called_urls = []
    payload = command_exec.COMMAND_PAYLOADS[0]

    def fake_get(u):
        called_urls.append(u)
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        if (
            qs.get("id", [None])[0] == payload
            and qs.get("Submit", [None])[0] == "Submit"
            and qs.get("hidden_field", [None])[0] == "foo"
        ):
            return DummyResponse("uid=1000(guy) gid=1000(guy) groups=1000(guy)")
        return DummyResponse("normal page")

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, None, inj_point, soup)
    assert any(
        r.vulnerability == command_exec.Vulnerabilities.COMMAND_EXECUTION_CONFIRMED
        for r in results
    )
    assert any(
        "id=%3Bid" in u and "Submit=Submit" in u and "hidden_field=foo" in u
        for u in called_urls
    )


def test_command_exec_post_form_fields_preserved(monkeypatch):
    from bs4 import BeautifulSoup

    url = "http://test/"
    inj_point = InjectionPoint(url, "id", "POST", "1")
    html = """
    <form action="#" method="POST">
        <input type="text" name="id" value="1">
        <input type="submit" name="Submit" value="Submit">
        <input type="hidden" name="hidden_field" value="foo">
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    called = {"params": None}
    payload = command_exec.COMMAND_PAYLOADS[0]

    class DummyPostResponse:
        def __init__(self, text):
            self.text = text

    def fake_post(url, data=None):
        called["params"] = data
        if (
            data.get("id") == payload
            and data.get("Submit") == "Submit"
            and data.get("hidden_field") == "foo"
        ):
            return DummyPostResponse("uid=1000(guy) gid=1000(guy) groups=1000(guy)")
        return DummyPostResponse("normal page")

    monkeypatch.setattr("yawast.shared.network.http_post", fake_post)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, None, inj_point, soup)
    assert any(
        r.vulnerability == command_exec.Vulnerabilities.COMMAND_EXECUTION_CONFIRMED
        for r in results
    )
    assert called["params"]["id"] in command_exec.COMMAND_PAYLOADS
    assert called["params"]["Submit"] == "Submit"
    assert called["params"]["hidden_field"] == "foo"


def test_command_exec_empty_response(monkeypatch):
    url = "http://test/?q=foo"
    inj_point = InjectionPoint(url, "q", "GET", "foo")

    def fake_get(u):
        return DummyResponse("")

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    if hasattr(command_exec.check_injection, "_tested_combinations"):
        command_exec.check_injection._tested_combinations.clear()
    results = command_exec.check_injection(url, None, inj_point, None)
    assert results == []
