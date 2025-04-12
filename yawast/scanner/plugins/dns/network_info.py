#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import Dict, Any

import pkg_resources

_cache: Dict[Any, Any] = {}
_data: Dict[Any, Any] = {}


def network_info(ip):
    """
    Retrieves ASN network information for a given IP address.

    This function checks a cache for the IP address first. If the IP is not
    found in the cache, it loads ASN data from a file (if not already loaded),
    and searches for the IP address within the loaded data. If a match is found,
    the corresponding country and description are cached and returned.

    Args:
        ip (str): The IP address to retrieve network information for.

    Returns:
        str: A string containing the country and description of the network
             associated with the given IP address, formatted as
             "Country - Description".
    """
    global _cache, _data

    # first, check the cache
    if _cache.get(ip) is not None:
        return _cache[ip]

    # load the data, if needed
    if len(_data) == 0:
        _build_data_from_file()

    # find the IP in the data
    for start in _data.keys():
        if _is_ip_in_range(ip, start, _data[start]["end"]):
            _cache[ip] = f"{_data[start]['country']} - {_data[start]['desc']}"

            return _cache[ip]


def purge_data():
    global _data

    # clear the data
    _data = {}


def _build_data_from_file():
    # load the IP range to ASN mapping
    # this is a TSV file, with the following columns:
    # 0 - Start IP
    # 1 - End IP
    # 2 - ASN Number
    # 3 - Country Code
    # 4 - ASN Description
    file_path = pkg_resources.resource_filename(
        "yawast", "resources/ip2asn-combined.tsv"
    )
    with open(file_path, "r") as file:
        for line in file:
            # ignore comments
            if not line or line[0] == "#":
                continue

            # split only the first 4 tabs, so we don't create extra string objects
            parts = line.rstrip("\n").split("\t", 4)
            if len(parts) < 5:
                continue

            start_ip, end_ip, _, country, desc = parts
            start = _convert_ip_to_int(start_ip)
            end = _convert_ip_to_int(end_ip)

            _data[start] = {
                "end": end,
                "country": country.strip(),
                "desc": desc.strip(),
            }


def _ipv4_to_int(ip):
    parts = ip.split(".")
    val = 0
    for part in parts:
        val = (val << 8) | int(part)
    return val


def _ipv6_to_int(ip):
    if "::" in ip:
        left, _, right = ip.partition("::")
        left_side = left.split(":") if left else []
        right_side = right.split(":") if right else []
        missing = 8 - (len(left_side) + len(right_side))
        parts = left_side + (["0"] * missing) + right_side
    else:
        parts = ip.split(":")

    val = 0
    for part in parts:
        val = (val << 16) | int(part, 16)
    return val


def _is_ipv6_in_range(ip, start, end):
    # convert the IP to an integer
    ip_int = _convert_ip_to_int(ip)

    # check if the IP is in the range
    if start <= ip_int <= end:
        return True

    return False


def _is_ipv4_in_range(ip, start, end):
    # convert the IP to an integer
    ip_int = _convert_ip_to_int(ip)

    # check if the IP is in the range
    if start <= ip_int <= end:
        return True

    return False


def _convert_ip_to_int(ip):
    if ":" in ip:
        # IPv6
        return _ipv6_to_int(ip)
    else:
        # IPv4
        return _ipv4_to_int(ip)


def _is_ip_in_range(ip, start, end):
    # check if the IP is in the range, supporting IPv4 and IPv6
    if ":" in ip:
        # IPv6
        if _is_ipv6_in_range(ip, start, end):
            return True
    else:
        # IPv4
        if _is_ipv4_in_range(ip, start, end):
            return True
