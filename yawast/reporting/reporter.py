import json
import os
import time
import zipfile
from datetime import datetime
from typing import Dict, List, cast, Optional, Any, Union
from zipfile import ZipFile

from yawast.external.memory_size import Size
from yawast.reporting.enums import Vulnerabilities, Severity
from yawast.reporting.issue import Issue
from yawast.scanner.plugins.result import Result
from yawast.shared import output

_issues: Dict[str, Dict[Vulnerabilities, List[Issue]]] = {}
_info: Dict[str, Any] = {}
_domain: str = ""
_output_file: str = ""


def init(output_file: Union[str, None] = None) -> None:
    global _output_file

    if output_file is not None:
        # if we have something, let's figure out what
        output_file = os.path.abspath(output_file)
        if os.path.isdir(output_file):
            # it's a directory, so we are going to create a name
            name = f"yawast_{int(time.time())}.json"
            output_file = os.path.join(output_file, name)
        elif os.path.isfile(output_file) or os.path.isfile(f"{_output_file}.zip"):
            # the file already exists
            print("WARNING: Output file already exists; it will be replaced.")

        _output_file = output_file


def save_output():
    global _issues, _info, _output_file

    vulns = {}
    for vuln in Vulnerabilities:
        vulns[vuln.name] = {"severity": vuln.severity, "description": vuln.description}

    data = {
        "info": _convert_keys(_info),
        "issues": _convert_keys(_issues),
        "vulnerabilities": vulns,
    }
    json_data = json.dumps(data, sort_keys=True, indent=4)

    try:
        zf = ZipFile(f"{_output_file}.zip", "x", zipfile.ZIP_LZMA)
        zf.writestr(f"{os.path.basename(_output_file)}", json_data)
        zf.close()

        orig = "{0:cM}".format(Size(len(json_data)))
        comp = "{0:cM}".format(Size(os.path.getsize(f"{_output_file}.zip")))
        print(f"Saving {_output_file}.zip... (size reduced from {orig} to {comp})")
    except Exception as error:
        print(f"Error writing output file: {error}")


def get_output_file() -> str:
    global _output_file

    if len(_output_file) > 0:
        return f"{_output_file}.zip"
    else:
        return ""


def setup(domain: str) -> None:
    global _domain, _issues

    _domain = domain

    _issues[_domain] = {}


def is_registered(vuln: Vulnerabilities) -> bool:
    global _issues, _domain

    if _issues is None:
        return False
    else:
        if _domain in _issues:
            if _issues[_domain].get(vuln) is None:
                return False
            else:
                return True
        else:
            return False


def register_info(key: str, value: Any):
    global _info

    _info[key] = value


def register_message(value: str, kind: str):
    global _info

    if "messages" not in _info:
        _info["messages"] = {}

    if kind not in _info["messages"]:
        _info["messages"][kind] = []

    _info["messages"][kind].append(f"[{datetime.utcnow()} UTC]: {value}")


def register(issue: Issue) -> None:
    global _issues, _domain

    # make sure the Dict for _domain exists - this shouldn't normally be an issue, but is for unit tests
    if _domain not in _issues:
        _issues[_domain] = {}

    # if we haven't handled this issue yet, create a List for it
    if not is_registered(issue.vulnerability):
        _issues[_domain][issue.vulnerability] = []

    # we need to check to see if we already have this issue, for this URL, so we don't create dups
    # TODO: This isn't exactly efficient - refactor
    findings = _issues[_domain][issue.vulnerability]
    findings = cast(List[Issue], findings)
    for finding in findings:
        if finding.url == issue.url and finding.evidence == issue.evidence:
            # just bail out
            output.debug(f"Duplicate Issue: {issue.id} (duplicate of {finding.id})")

            return

    _issues[_domain][issue.vulnerability].append(issue)
    output.debug(
        f"Issue Registered: {issue.id} - {issue.vulnerability.name} - {issue.url}"
    )


def display(msg: str, issue: Issue) -> None:
    if issue.vulnerability.display_all or not is_registered(issue.vulnerability):
        if issue.severity == Severity.CRITICAL or issue.severity == Severity.HIGH:
            output.vuln(msg)
        elif issue.severity == Severity.MEDIUM or issue.severity == Severity.LOW:
            output.warn(msg)
        else:
            output.info(msg)

    # if there's no evidence, default to the msg - better than nothing
    if issue.evidence is None:
        issue.evidence = msg.strip()

    register(issue)


def display_results(results: List[Result], padding: Optional[str] = ""):
    for res in results:
        iss = Issue.from_result(res)
        display(f"{padding}{res.message}", iss)


def _convert_keys(dct: Dict) -> Dict:
    ret = {}

    for k, v in dct.items():
        if type(k) is Vulnerabilities:
            k = k.name

        if type(v) is dict:
            v = _convert_keys(v)

        ret[k] = v

    return ret
