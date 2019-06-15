import uuid
from typing import Union, List

from yawast.reporting.enums import Vulnerabilities
from yawast.shared import output


class Result:
    def __init__(
        self,
        msg: str,
        vuln: Vulnerabilities,
        url: str,
        evidence: Union[str, List[str], None] = None,
    ):
        self.message = msg
        self.vulnerability = vuln
        self.url = url

        if evidence is not None:
            self.evidence = evidence

            # if the evidence is a string, lets tack on the message as an extra element
            if type(evidence) is str:
                self.evidence = [evidence, msg]
        else:
            # fall back to the message if we don't have evidence - better than nothing
            self.evidence = msg

        self.id = uuid.uuid4().hex

        output.debug(
            f"Result Created: {self.id} - {self.vulnerability.name} - {self.url}"
        )

    def __repr__(self):
        return f"Result: {self.id} - {self.vulnerability.name} - {self.url} - {self.message}"
