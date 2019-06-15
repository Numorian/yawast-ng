import uuid
from typing import Union, List, cast

from yawast.reporting.enums import Vulnerabilities, VulnerabilityInfo
from yawast.scanner.plugins.result import Result
from yawast.shared import output


class Issue:
    def __init__(
        self,
        vuln: Vulnerabilities,
        url: str,
        evidence: Union[str, List[str], None] = None,
    ):
        val = cast(VulnerabilityInfo, vuln.value)

        self.vulnerability = vuln
        self.severity = val.severity
        self.url = url
        self.evidence = evidence
        self.description = val.description
        self.id = uuid.uuid4().hex

        output.debug(
            f"Issue Created: {self.id} - {self.vulnerability.name} - {self.url}"
        )

    def __repr__(self):
        return f"Result: {self.id} - {self.vulnerability.name} - {self.url}"

    @classmethod
    def from_result(cls, result: Result):
        iss = cls(result.vulnerability, result.url, result.evidence)

        output.debug(f"Issue {iss.id} created from result {result.id}")

        return iss
