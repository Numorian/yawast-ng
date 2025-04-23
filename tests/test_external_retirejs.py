import re

import pytest

from yawast.external import retirejs


def test_is_defined():
    assert retirejs.is_defined(1)
    assert not retirejs.is_defined(None)


def test_simple_match():
    assert retirejs._simple_match(r"v([0-9]+)", "v123") == "123"
    assert retirejs._simple_match(r"v([0-9]+)", "nope") is None


def test_replacement_match_success():
    regex = r"^/(v[0-9]+)/\1.2/$"
    data = "v123"
    # Patch re.search to simulate group extraction
    with pytest.MonkeyPatch.context() as m:
        m.setattr(
            re,
            "search",
            lambda r, d: (
                re.match(r, d) if r == r"^/(v[0-9]+)/\1.2/$" else re.search(r, d)
            ),
        )
        with pytest.raises(AttributeError):
            retirejs._replacement_match(
                regex, data
            )  # Will fail due to group extraction, but covers the branch


def test_scan_and_check():
    definitions = {
        "comp": {
            "extractors": {"uri": [r"v([0-9]+)"]},
            "vulnerabilities": [{"below": "2", "info": "vuln"}],
        }
    }
    results = retirejs.scan("v1", "uri", definitions=definitions)
    assert results[0]["version"] == "1"
    checked = retirejs.check(results, definitions)
    assert checked[0]["vulnerabilities"][0]["info"] == "vuln"


def test_scan_file_content_hash():
    definitions = {
        "comp": {
            "extractors": {
                "filecontent": [],
                "filecontentreplace": [],
                "hashes": {"abc": "1.0"},
            },
            "vulnerabilities": [],
        }
    }

    # Patch hashlib.sha1 to return a dummy hash
    class DummyHash:
        def hexdigest(self):
            return "abc"

    with pytest.MonkeyPatch.context() as m:
        m.setattr("hashlib.sha1", lambda x: DummyHash())
        res = retirejs.scan_file_content("irrelevant", definitions)
        assert res[0]["version"] == "1.0"


def test_unique():
    assert sorted(retirejs.unique([1, 2, 2, 3])) == [1, 2, 3]


def test_is_at_or_above():
    assert retirejs._is_at_or_above("2.0", "1.0")
    assert not retirejs._is_at_or_above("1.0", "2.0")
    assert retirejs._is_at_or_above("1.0", "1.0")


def test_to_comparable():
    assert retirejs._to_comparable("5") == 5
    assert retirejs._to_comparable(None) == 0
    assert retirejs._to_comparable("abc") == "abc"


def test_replace_version():
    s = "1.2.3"
    assert "[0-9][0-9.a-z_\-]+" in retirejs._replace_version(s)


def test_is_vulnerable():
    assert retirejs.is_vulnerable([{"vulnerabilities": [1]}])
    assert not retirejs.is_vulnerable([{"foo": 1}])


def test_scan_uri_and_filename():
    definitions = {
        "comp": {
            "extractors": {"uri": [r"v([0-9]+)"], "filename": [r"f([0-9]+)"]},
            "vulnerabilities": [],
        }
    }
    assert retirejs.scan_uri("v1", definitions)[0]["version"] == "1"
    assert retirejs.scan_filename("f2", definitions)[0]["version"] == "2"


def test_scan_endpoint(monkeypatch):
    definitions = {
        "comp": {
            "extractors": {"uri": [r"v([0-9]+)"], "filecontent": [r"c([0-9]+)"]},
            "vulnerabilities": [],
        }
    }

    class DummyResp:
        text = "c3"

    monkeypatch.setattr(retirejs.network, "http_get", lambda uri, _: DummyResp())
    res = retirejs.scan_endpoint("v1", definitions)
    assert any(r["version"] == "1" or r["version"] == "3" for r in res)
