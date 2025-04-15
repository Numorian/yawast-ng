#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import bisect
import ipaddress
from typing import Any, Dict

import pkg_resources

_data: Dict[Any, Any] = None


def network_info(ip):
    global _data

    ip_int = int(ipaddress.ip_address(ip))

    if _data is None:
        _build_data_from_file()

    # use binary search to find the rightmost record whose 'start_int' is <= ip_int
    # the records are tuples; binary search only uses the first element (start_int) for comparisons
    i = bisect.bisect_right(_data, (ip_int,)) - 1

    if i >= 0:
        start_int, end_int, description = _data[i]
        # If the provided IP (in integer form) lies within the range, return the info.
        if start_int <= ip_int <= end_int:
            return description

    return "Unknown"


def purge_data():
    global _data

    # clear the data
    _data = None


def _build_data_from_file():
    # load the IP range to ASN mapping
    # this is a TSV file, with the following columns:
    # 0 - Start IP
    # 1 - End IP
    # 4 - Country Code - ASN Description

    global _data
    _data = []

    file_path = pkg_resources.resource_filename(
        "yawast", "resources/ip2asn-combined.tsv"
    )

    with open(file_path, "r") as f:
        for line in f:
            # remove any extra whitespace; skip empty or malformed lines
            parts = line.strip().split("\t")
            if len(parts) < 3:
                continue

            try:
                start_int = int(parts[0])
                end_int = int(parts[1])
            except ValueError:
                # skip lines with invalid IP addresses
                continue

            description = parts[2]
            _data.append((start_int, end_int, description))

    # sort the data to make sure binary search can be used
    _data.sort(key=lambda record: record[0])
