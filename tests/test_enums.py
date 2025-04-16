import unittest
from unittest import mock

from yawast.reporting.enums import Severity, Vulnerabilities, VulnerabilityInfo


class TestVulnerabilitiesAdd(unittest.TestCase):
    @mock.patch("yawast.reporting.enums.extend_enum")
    @mock.patch.object(VulnerabilityInfo, "create")
    def test_add_calls_extend_enum_with_correct_arguments(
        self, mock_create, mock_extend_enum
    ):
        # Arrange
        name = "Test_Vuln"
        severity = Severity.LOW
        description = "Test description"
        fake_vuln_info = mock.Mock()
        mock_create.return_value = fake_vuln_info

        # Act
        Vulnerabilities.add(name, severity, description)

        # Assert
        mock_create.assert_called_once_with(name, severity, description)
        mock_extend_enum.assert_called_once_with(Vulnerabilities, name, fake_vuln_info)

    def test_add_creates_vulnerability_info(self):
        # Arrange
        name = "Test_Create_Vuln"
        severity = Severity.LOW
        description = "Test description"

        # Act
        Vulnerabilities.add(name, severity, description)
        vuln_info = Vulnerabilities.Test_Create_Vuln

        # Assert
        self.assertIsInstance(vuln_info, VulnerabilityInfo)
        self.assertEqual(vuln_info.name, name)
        self.assertEqual(vuln_info.severity, severity)
        self.assertEqual(vuln_info.description, description)
