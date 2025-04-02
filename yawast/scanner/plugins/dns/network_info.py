#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import Dict, Any

import pkg_resources

from yawast.shared import network, output

_failure = False
_cache: Dict[Any, Any] = {}
_data: Dict[Any, Any] = {}


def network_info(ip):
    global _failure, _cache, _data

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
            if line.startswith("#"):
                continue

            parts = line.split("\t")

            if len(parts) < 5:
                continue

            start = _convert_ip_to_int(parts[0].strip())
            end = _convert_ip_to_int(parts[1].strip())
            asn = parts[2].strip()
            country = parts[3].strip()
            desc = parts[4].strip()

            _data[start] = {"end": end, "asn": asn, "country": country, "desc": desc}


def _ipv6_to_int(ip):
    # pad truncated IPs
    if "::" in ip:
        ip = ip.replace("::", ":" + ("0:" * (8 - ip.count(":"))))

    # split the IP into its 8 parts
    parts = ip.split(":")

    # convert each part to a 4-digit hex value
    hex_parts = []
    for part in parts:
        hex_parts.append(part.zfill(4))

    # join the parts together
    hex_str = "".join(hex_parts)

    # convert to a number
    return int(hex_str, 16)


def _ipv4_to_int(ip):
    # split the IP into its 4 parts
    parts = ip.split(".")

    # convert each part to a 3-digit hex value
    hex_parts = []
    for part in parts:
        hex_parts.append(part.zfill(3))

    # join the parts together
    hex_str = "".join(hex_parts)

    # convert to an integer
    return int(hex_str, 16)


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
