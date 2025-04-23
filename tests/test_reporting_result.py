from yawast.reporting.enums import VulnerabilityInfo
from yawast.reporting.evidence import Evidence
from yawast.reporting.result import Result


def make_vuln():
    return VulnerabilityInfo(
        name="TestVuln",
        severity="high",
        description="desc",
        solution="sol",
        references=[],
    )


def test_result_init_evidence_obj():
    vuln = make_vuln()
    ev = Evidence("http://foo", "req", "resp", {"x": 1})
    r = Result("msg", vuln, "http://foo", ev)
    assert r.evidence == ev
    assert r.message == "msg"
    assert r.vulnerability == vuln
    assert r.url == "http://foo"
    assert "TestVuln" in repr(r)


def test_result_init_evidence_dict():
    vuln = make_vuln()
    ev = {"request": "req", "response": "resp", "foo": "bar"}
    r = Result("msg", vuln, "http://foo", ev)
    assert isinstance(r.evidence, Evidence)
    assert r.evidence.request == "req"
    assert r.evidence.response == "resp"
    assert r.evidence.custom["foo"] == "bar"


def test_result_init_evidence_str():
    vuln = make_vuln()
    r = Result("msg", vuln, "http://foo", "evstr")
    assert isinstance(r.evidence, Evidence)
    assert r.evidence.custom["e"] == "evstr"
    assert r.evidence.custom["message"] == "msg"


def test_result_init_evidence_other():
    vuln = make_vuln()
    r = Result("msg", vuln, "http://foo", 123)
    assert isinstance(r.evidence, Evidence)
    assert r.evidence.custom["e"] == 123


def test_result_init_evidence_none():
    vuln = make_vuln()
    r = Result("msg", vuln, "http://foo")
    assert isinstance(r.evidence, Evidence)
    assert r.evidence.custom["message"] == "msg"


def test_result_from_evidence():
    vuln = make_vuln()
    ev = Evidence("http://foo", "req", "resp")
    r = Result.from_evidence(ev, "msg", vuln)
    assert isinstance(r, Result)
    assert r.evidence == ev
    assert r.message == "msg"
