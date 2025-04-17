#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import uuid
from typing import Any, Dict, List, Union

from yawast.reporting.enums import VulnerabilityInfo
from yawast.reporting.evidence import Evidence


class Result:
    evidence: Evidence
    url: str
    vulnerability: VulnerabilityInfo
    message: str

    def __init__(
        self,
        msg: str,
        vuln: VulnerabilityInfo,
        url: str,
        evidence: Union[str, List[str], Dict[str, Any], Evidence, None] = None,
    ):
        self.message = msg
        self.vulnerability = vuln
        self.url = url

        if evidence is not None:
            if isinstance(evidence, Evidence):
                self.evidence = evidence
            elif isinstance(evidence, dict):
                # create a new evidence object from the dictionary
                request = None
                if "request" in evidence:
                    request = evidence["request"]

                response = None
                if "response" in evidence:
                    response = evidence["response"]

                custom = None
                # get any other data and add it to the custom dict
                if len(evidence) > 3:
                    custom = {
                        k: v
                        for k, v in evidence.items()
                        if k not in ["request", "response", "url"]
                    }

                self.evidence = Evidence(url, request, response, custom)
            elif isinstance(evidence, str):
                # if the evidence is a string, lets tack on the message as an extra element
                custom = {"e": str(evidence), "message": msg}

                self.evidence = Evidence(url, None, None, custom)
            else:
                custom = self.evidence = {"e": evidence}

                self.evidence = Evidence(url, None, None, custom)
        else:
            # fall back to the message if we don't have evidence - better than nothing
            custom = {"message": msg}
            self.evidence = Evidence(url, None, None, custom)

        self.id = uuid.uuid4().hex

    def __repr__(self):
        return f"Result: {self.id} - {self.vulnerability.name} - {self.url} - {self.message}"

    @classmethod
    def from_evidence(cls, ev: Evidence, msg: str, vuln: VulnerabilityInfo):
        r = cls(msg, vuln, ev.url, ev)

        return r
