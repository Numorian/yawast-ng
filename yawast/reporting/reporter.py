from typing import Dict, List, cast, Optional
from yawast.shared import output
from yawast.reporting.enums import Vulnerabilities, Severity
from yawast.reporting.issue import Issue
from yawast.scanner.plugins.result import Result

_issues: Dict[str, Dict[Vulnerabilities, List[Issue]]] = {}
_domain: str = ""


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
