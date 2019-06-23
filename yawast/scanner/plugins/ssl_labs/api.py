from typing import Tuple, Dict, Any, List

from yawast.shared import network, output

API_SERVER = "https://api.ssllabs.com"


def get_info_message() -> List[str]:
    path = "/api/v3/info"
    messages: List[str] = []

    try:
        body, code = network.http_json(API_SERVER + path)

        if len(body["messages"]) > 0:
            for msg in body["messages"]:
                messages.append(msg)
    except Exception:
        output.debug_exception()
        raise

    return messages


def start_scan(domain: str) -> Tuple[str, Dict[str, Any]]:
    resp = _analyze(domain, True)
    status = resp["status"]

    output.debug(f"Started SSL Labs scan: {resp}")

    return status, resp


def check_scan(domain: str) -> Tuple[str, Dict[str, Any]]:
    resp = _analyze(domain)
    status = resp["status"]

    if status != "READY":
        output.debug(f"SSL Labs status: {resp}")

    return status, resp


def _analyze(domain: str, new=False) -> Dict[str, Any]:
    new_path = "host={target}&publish=off&startNew=on&all=done&ignoreMismatch=on".format(
        target=domain
    )
    status_path = "host={target}&publish=off&all=done&ignoreMismatch=on".format(
        target=domain
    )

    if new:
        path = new_path
    else:
        path = status_path

    try:
        body, code = network.http_json(API_SERVER + "/api/v3/analyze?" + path)
    except Exception:
        output.debug_exception()
        raise

    # check for error messages
    if body.get("errors") is not None:
        raise ValueError(
            "SSL Labs returned the following error(s): {errors}".format(
                errors=str(body["errors"])
            )
        )

    # next up, check to see what error code we have
    if code != 200:
        # if we got anything but 200, it's a problem
        raise ValueError("SSL Labs returned error code: {code}".format(code=code))

    return body
