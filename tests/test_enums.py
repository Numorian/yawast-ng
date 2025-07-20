import pytest

from yawast.reporting.enums import (
    Severity,
    Vulnerabilities,
    VulnerabilityInfo,
    VulnerabilityReference,
)
from yawast.reporting.evidence import Evidence
from yawast.reporting.issue import Issue


class TestVulnerabilitiesAdd:
    def test_add_creates_vulnerability_info(self):
        # Arrange
        name = "Test_Create_Vuln"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN

        # Assert
        assert isinstance(vuln_info, VulnerabilityInfo)
        assert vuln_info.name == name
        assert vuln_info.severity == severity
        assert vuln_info.description == description

    def test_add_vulnerability_issue(self):
        # Arrange
        name = "Test_Create_Vuln_Issue"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN_ISSUE

        ev = Evidence("https://numorian.com", None, None)
        issue = Issue(Vulnerabilities.TEST_CREATE_VULN_ISSUE, "https//numorian.com", ev)

        # Assert
        assert isinstance(vuln_info, VulnerabilityInfo)
        assert vuln_info.name == name
        assert vuln_info.severity == severity
        assert vuln_info.description == description
        assert issue.vulnerability == Vulnerabilities.TEST_CREATE_VULN_ISSUE

    def test_add_vulnerability_issue_ref(self):
        # Arrange
        name = "Test_Create_Vuln_Issue_Ref"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN_ISSUE_REF

        ev = Evidence("https://numorian.com", None, None)
        issue = Issue(Vulnerabilities.get(name), "https//numorian.com", ev)

        # Assert
        assert isinstance(vuln_info, VulnerabilityInfo)
        assert vuln_info.name == name
        assert vuln_info.severity == severity
        assert vuln_info.description == description
        assert issue.vulnerability == Vulnerabilities.TEST_CREATE_VULN_ISSUE_REF


def test_severity_enum():
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert Severity.MEDIUM == "medium"
    assert Severity.LOW == "low"
    assert Severity.BEST_PRACTICE == "best_practice"
    assert Severity.INFO == "info"


def test_vulnerability_reference():
    ref = VulnerabilityReference("CVE-1234", "https://numorian.com")
    assert ref.name == "CVE-1234"
    assert ref.url == "https://numorian.com"


def test_vulnerability_info_create_and_hash():
    vi = VulnerabilityInfo.create("Test", Severity.LOW, "desc")
    assert vi.name == "Test"
    assert vi.severity == Severity.LOW
    assert vi.description == "desc"
    assert vi.id.startswith("Y")
    assert isinstance(hash(vi), int)


def test_vulnerabilities_get_and_all():
    vi = Vulnerabilities.get("App_WordPress_Version")
    assert isinstance(vi, VulnerabilityInfo)
    all_vulns = Vulnerabilities.all()
    assert any(isinstance(v, VulnerabilityInfo) for v in all_vulns)


def test_vulnerabilities_add():
    Vulnerabilities.add("Test_Add", Severity.INFO, "desc")
    vi = Vulnerabilities.get("Test_Add")
    assert isinstance(vi, VulnerabilityInfo)
    assert vi.name == "Test_Add"
