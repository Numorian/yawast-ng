# From: https://github.com/FallibleInc/retirejslib/blob/master/retirejs/retirejs.py
# License: Apache-2.0
# Copyright: Fallible Inc

import hashlib
import re

from ..shared import network, output


def is_defined(o):
    return o is not None


def scan(data, extractor, matcher=None, definitions=None):
    matcher = matcher or _simple_match
    detected = []
    for component in definitions:
        extractors = definitions[component].get("extractors", None).get(extractor, None)
        if not is_defined(extractors):
            continue
        for i in extractors:
            match = matcher(i, data)
            if match:
                detected.append(
                    {"version": match, "component": component, "detection": extractor}
                )
    return detected


def _simple_match(regex, data):
    match = re.search(regex, data)
    return match.group(1) if match else None


def _replacement_match(regex, data):
    group_parts_of_regex = r"^\/(.*[^\\])\/([^\/]+)\/$"
    ar = re.search(group_parts_of_regex, regex)
    search_for_regex = ar.group(1)

    try:
        match = re.search(search_for_regex, data)
    except Exception as e:
        output.debug("retirejs regex error: " + str(e))
        output.debug("  regex: " + regex)
        output.debug("  search_for_regex: " + search_for_regex)

        raise e

    if match:
        ver = re.sub(ar.group(1), ar.group(2), match.group(0))
        return ver

    return None


def _scanhash(hsh, definitions):
    for component in definitions:
        hashes = definitions[component].get("extractors", None).get("hashes", None)
        if not is_defined(hashes):
            continue
        for i in hashes:
            if i == hsh:
                return [
                    {"version": hashes[i], "component": component, "detection": "hash"}
                ]

    return []


def check(results, definitions):
    for r in results:
        result = r

        if not is_defined(definitions[result.get("component", None)]):
            continue
        vulns = definitions[result.get("component", None)].get("vulnerabilities", None)
        for i in range(len(vulns)):
            if not _is_at_or_above(
                result.get("version", None), vulns[i].get("below", None)
            ):
                if is_defined(vulns[i].get("atOrAbove", None)) and not _is_at_or_above(
                    result.get("version", None), vulns[i].get("atOrAbove", None)
                ):
                    continue

                vulnerability = {"info": vulns[i].get("info", None)}
                if vulns[i].get("severity", None):
                    vulnerability["severity"] = vulns[i].get("severity", None)

                if vulns[i].get("identifiers", None):
                    vulnerability["identifiers"] = vulns[i].get("identifiers", None)

                result["vulnerabilities"] = result.get("vulnerabilities", None) or []
                result["vulnerabilities"].append(vulnerability)

    return results


def unique(ar):
    return list(set(ar))


def _is_at_or_above(version1, version2):
    # print "[",version1,",", version2,"]"
    v1 = re.split(r"[.-]", version1)
    v2 = re.split(r"[.-]", version2)

    l = len(v1) if len(v1) > len(v2) else len(v2)
    for i in range(l):
        v1_c = _to_comparable(v1[i] if len(v1) > i else None)
        v2_c = _to_comparable(v2[i] if len(v2) > i else None)
        # print v1_c, "vs", v2_c
        if not isinstance(v1_c, type(v2_c)):
            return isinstance(v1_c, int)
        if v1_c > v2_c:
            return True
        if v1_c < v2_c:
            return False

    return True


def _to_comparable(n):
    if not is_defined(n):
        return 0
    if re.search(r"^[0-9]+$", n):
        return int(str(n), 10)

    return n


def _replace_version(jsRepoJsonAsText):
    return re.sub(r"[.0-9]*", r"[0-9][0-9.a-z_\-]+", jsRepoJsonAsText)


def is_vulnerable(results):
    for r in results:
        if "vulnerabilities" in r:
            # print r
            return True

    return False


def scan_uri(uri, definitions):
    result = scan(uri, "uri", definitions=definitions)
    return check(result, definitions)


def scan_filename(fileName, definitions):
    result = scan(fileName, "filename", definitions=definitions)
    return check(result, definitions)


def scan_file_content(content, definitions):
    result = scan(content, "filecontent", definitions=definitions)
    if len(result) == 0:
        result = scan(content, "filecontentreplace", _replacement_match, definitions)

    if len(result) == 0:
        result = _scanhash(
            hashlib.sha1(content.encode("utf8")).hexdigest(), definitions
        )

    return check(result, definitions)


def scan_endpoint(uri, definitions):
    """
    Given a uri it scans for vulnerability in uri and the content
    hosted at that uri
    """
    uri_scan_result = scan_uri(uri, definitions)

    filecontent = network.http_get(uri, False).text
    filecontent_scan_result = scan_file_content(filecontent, definitions)

    uri_scan_result.extend(filecontent_scan_result)
    return uri_scan_result
