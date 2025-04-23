from yawast.reporting.enums import VulnerabilityInfo
from yawast.reporting.evidence import Evidence
from yawast.reporting.issue import Issue
from yawast.reporting.result import Result


def make_vuln():
    return VulnerabilityInfo(
        name="TestVuln",
        severity="high",
        description="desc",
        solution="sol",
        references=[],
    )


def make_evidence():
    return Evidence("test", None, None)


def test_issue_init_and_repr():
    vuln = make_vuln()
    evidence = make_evidence()
    issue = Issue(vuln, "http://example.com", evidence)
    assert issue["url"] == "http://example.com"
    assert issue["evidence"] == evidence
    assert issue.vulnerability == vuln
    assert issue.severity == "high"
    assert "TestVuln" in repr(issue)


def test_issue_from_result():
    vuln = make_vuln()
    evidence = make_evidence()
    result = Result("msg", vuln, "http://foo", evidence)
    issue = Issue.from_result(result)
    assert isinstance(issue, Issue)
    assert issue["url"] == "http://foo"
