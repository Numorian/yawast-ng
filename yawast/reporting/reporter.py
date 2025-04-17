#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import gc
import json
import os
import time
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, cast

from yawast import config
from yawast.external.memory_size import Size
from yawast.external.total_size import total_size
from yawast.reporting.enums import Severity, Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.issue import Issue
from yawast.reporting.result import Result
from yawast.shared import output
from yawast.shared.exec_timer import ExecutionTimer

_issues: Dict[str, Dict[Vulnerabilities, List[Issue]]] = {}
_info: Dict[str, Any] = {}
_data: Dict[str, Any] = {}
_domain: str = ""
_output_file: str = ""
_injection_points: Dict[str, List[InjectionPoint]] = {}


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


def save_output(spinner=None):
    # add some extra debug data
    register_info("memsize_issues", total_size(_issues))
    register_info("memsize_info", total_size(_info))
    register_info("memsize_data", total_size(_data))
    register_info("gc_stats", gc.get_stats())
    register_info("gc_objects", len(gc.get_objects()))

    if spinner:
        spinner.stop()
    print("Saving...")
    if spinner:
        spinner.start()

    vulns = {}
    for vuln in Vulnerabilities.all():
        vulns[vuln.name] = {
            "severity": vuln.severity,
            "description": vuln.description,
            "id": vuln.id,
        }

    # build evidence from the issues
    evidence = {}
    for domain in _issues:
        evidence[domain] = {}

        for vuln in _issues[domain]:
            for issue in _issues[domain][vuln]:
                if isinstance(issue.evidence, Evidence):
                    if issue.evidence.request_id is not None:
                        evidence[domain][
                            issue.evidence.request_id
                        ] = issue.evidence.request
                    if issue.evidence.response_id is not None:
                        evidence[domain][
                            issue.evidence.response_id
                        ] = issue.evidence.response

    issues = {}
    for domain in _issues:
        issues[domain] = {}

        for vuln in _issues[domain]:
            issues[domain][vuln.name] = []

            for issue in _issues[domain][vuln]:
                evidence_detail = {}

                if isinstance(issue.evidence, Evidence):
                    if issue.evidence.request_id is not None:
                        evidence_detail["request"] = issue.evidence.request_id
                    if issue.evidence.response_id is not None:
                        evidence_detail["response"] = issue.evidence.response_id
                    if issue.evidence.custom is not None:
                        evidence_detail.update(issue.evidence.custom)

                issue_detail = {
                    "id": issue.id,
                    "url": issue.url,
                    "evidence": evidence_detail,
                }

                issues[domain][vuln.name].append(issue_detail)

    # add the injection points
    injection_points = {}
    if len(_injection_points) > 0:
        for domain in _injection_points:
            injection_points[domain] = []

            for point in _injection_points[domain]:
                injection_points[domain].append(point.to_dict())

    register_data("injection_points", injection_points)

    data = {
        "_info": _convert_keys(_info),
        "data": _convert_keys(_data),
        "issues": issues,
        "evidence": evidence,
        "vulnerabilities": vulns,
    }
    json_data = json.dumps(data, indent=4)

    # clean up the temp files from the evidence
    for domain in _issues:
        for vuln in _issues[domain]:
            for issue in _issues[domain][vuln]:
                try:
                    if isinstance(issue.evidence, Evidence):
                        issue.evidence.purge_files()
                except Exception as error:
                    print(f"Error purging files: {error}")

    try:
        filename = _output_file

        # check to see if the zip file already exists
        if os.path.isfile(f"{filename}.zip"):
            # if it does, let's modify the name we are going to use
            original_file_name = os.path.basename(filename)
            name = f"{original_file_name}_{int(time.time())}.json"

            filename = os.path.join(os.path.dirname(_output_file), name)

        zf = zipfile.ZipFile(f"{filename}.zip", "x", zipfile.ZIP_BZIP2)

        with ExecutionTimer() as tm:
            zf.writestr(
                f"{os.path.basename(filename)}",
                json_data.encode("utf_8", "backslashreplace"),
            )

        zf.close()

        orig = "{0:cM}".format(Size(len(json_data)))
        comp = "{0:cM}".format(Size(os.path.getsize(f"{filename}.zip")))

        if spinner:
            spinner.stop()
        print(
            f"Saved {filename}.zip (size reduced from {orig} to {comp} in {tm.to_ms()}ms)"
        )
    except Exception as error:
        if spinner:
            spinner.stop()

        print(f"Error writing output file: {error}")


def get_output_file() -> str:
    if len(_output_file) > 0:
        return f"{_output_file}.zip"
    else:
        return ""


def setup(domain: str) -> None:
    global _domain

    _domain = domain

    if _domain not in _issues:
        _issues[_domain] = {}

    if _domain not in _data:
        _data[_domain] = {}


def is_registered(vuln: Vulnerabilities) -> bool:
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
    if _output_file is not None and len(_output_file) > 0:
        _info[key] = value


def register_data(key: str, value: Any):
    if _output_file is not None and len(_output_file) > 0:
        if _domain is not None:
            if _domain in _data:
                _register_data(_data[_domain], key, value)
            else:
                _data[_domain] = {}
                _register_data(_data[_domain], key, value)
        else:
            _register_data(_data, key, value)


def register_message(value: str, kind: str):
    if _output_file is not None and len(_output_file) > 0:
        if "messages" not in _info:
            _info["messages"] = {}

        if kind not in _info["messages"]:
            _info["messages"][kind] = []

        should_log = True
        if kind == "debug":
            if not config.include_debug_in_output:
                should_log = False

        if should_log:
            _info["messages"][kind].append(f"[{datetime.utcnow()} UTC]: {value}")


def register_injection_points(points: List[InjectionPoint]):
    if _output_file is not None and len(_output_file) > 0:
        if _domain not in _injection_points:
            _injection_points[_domain] = []

        _injection_points[_domain].extend(points)


def register(issue: Issue) -> None:
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

    # if we aren't saving evidence, we can remove some things to save memory
    if _output_file is None or len(_output_file) == 0:
        if "request" in issue.evidence:
            issue.evidence["request"] = ""
        if "response" in issue.evidence:
            issue.evidence["response"] = ""
    else:
        # if we need to keep this around, let's cache to disk
        try:
            if isinstance(issue.evidence, Evidence):
                issue.evidence.cache_to_file()
        except Exception as error:
            output.debug(f"Error caching evidence: {error}")

    _issues[_domain][issue.vulnerability].append(issue)


def display(msg: str, issue: Issue) -> None:
    if issue.vulnerability.display_all or not is_registered(issue.vulnerability):
        if issue.severity == Severity.CRITICAL or issue.severity == Severity.HIGH:
            output.vuln(msg)
        elif issue.severity == Severity.MEDIUM:
            output.warn(msg)
        else:
            output.info(msg)

    # if there's no evidence, default to the msg - better than nothing
    if issue.evidence is None:
        # TODO: This should be an Evidence object, not a string
        issue.evidence = msg.strip()

    register(issue)


def display_results(results: List[Result], padding: Optional[str] = ""):
    for res in results:
        iss = Issue.from_result(res)
        display(f"{padding}{res.message}", iss)


def _register_data(data: Dict, key: str, value: Any):
    if key in data and isinstance(data[key], list) and isinstance(value, list):
        ls = cast(list, data[key])
        ls.extend(value)
    elif key in data and isinstance(data[key], dict) and isinstance(value, dict):
        dt = cast(dict, data[key])
        dt.update(value)
    else:
        data[key] = value


def _convert_keys(dct: Dict) -> Dict:
    ret = {}

    for k, v in dct.items():
        if isinstance(k, Vulnerabilities):
            k = k.name

        if isinstance(v, dict):
            v = _convert_keys(v)

        try:
            _ = json.dumps(v)
        except Exception as error:
            output.debug(f"Error serializing data: {str(error)}")
            # convert to string - this may be wrong, but at least it won't fail
            v = str(v)

        ret[k] = v

    return ret
