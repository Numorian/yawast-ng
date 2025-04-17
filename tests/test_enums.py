import unittest
from unittest import mock

from yawast.reporting.enums import Severity, Vulnerabilities, VulnerabilityInfo
from yawast.reporting.evidence import Evidence
from yawast.reporting.issue import Issue


class TestVulnerabilitiesAdd(unittest.TestCase):
    def test_add_creates_vulnerability_info(self):
        # Arrange
        name = "Test_Create_Vuln"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN

        # Assert
        self.assertIsInstance(vuln_info, VulnerabilityInfo)
        self.assertEqual(vuln_info.name, name)
        self.assertEqual(vuln_info.severity, severity)
        self.assertEqual(vuln_info.description, description)

    def test_add_vulnerability_issue(self):
        # Arrange
        name = "Test_Create_Vuln_Issue"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN_ISSUE

        ev = Evidence("https://example.com", None, None)
        issue = Issue(Vulnerabilities.TEST_CREATE_VULN_ISSUE, "https//example.com", ev)

        # Assert
        self.assertIsInstance(vuln_info, VulnerabilityInfo)
        self.assertEqual(vuln_info.name, name)
        self.assertEqual(vuln_info.severity, severity)
        self.assertEqual(vuln_info.description, description)
        self.assertEqual(issue.vulnerability, Vulnerabilities.TEST_CREATE_VULN_ISSUE)

    def test_add_vulnerability_issue_ref(self):
        # Arrange
        name = "Test_Create_Vuln_Issue_Ref"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.TEST_CREATE_VULN_ISSUE_REF

        ev = Evidence("https://example.com", None, None)
        issue = Issue(Vulnerabilities.get(name), "https//example.com", ev)

        # Assert
        self.assertIsInstance(vuln_info, VulnerabilityInfo)
        self.assertEqual(vuln_info.name, name)
        self.assertEqual(vuln_info.severity, severity)
        self.assertEqual(vuln_info.description, description)
        self.assertEqual(
            issue.vulnerability, Vulnerabilities.TEST_CREATE_VULN_ISSUE_REF
        )
