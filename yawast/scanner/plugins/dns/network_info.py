#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import Dict, Any

import pkg_resources, bisect, ipaddress

_data: Dict[Any, Any] = None


def network_info(ip):
    global _data

    ip_int = _ip_to_int(ip)

    if _data is None:
        _build_data_from_file()

    # use binary search to find the rightmost record whose 'start_int' is <= ip_int
    # the records are tuples; binary search only uses the first element (start_int) for comparisons
    i = bisect.bisect_right(_data, (ip_int,)) - 1

    if i >= 0:
        start_int, end_int, country, asn_description = _data[i]
        # If the provided IP (in integer form) lies within the range, return the info.
        if start_int <= ip_int <= end_int:
            return f"{country} - {asn_description}"

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
    # 2 - ASN Number
    # 3 - Country Code
    # 4 - ASN Description

    global _data
    _data = []

    file_path = pkg_resources.resource_filename(
        "yawast", "resources/ip2asn-combined.tsv"
    )

    with open(file_path, "r") as f:
        for line in f:
            # remove any extra whitespace; skip empty or malformed lines
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue

            try:
                # convert start and end IP addresses to integers
                start_int = _ip_to_int(parts[0])
                end_int = _ip_to_int(parts[1])
            except ValueError:
                # skip lines with invalid IP addresses
                continue

            # extract the country code and ASN description
            country = parts[3]
            asn_description = parts[4]
            _data.append((start_int, end_int, country, asn_description))

    # sort the data to make sure binary search can be used
    _data.sort(key=lambda record: record[0])


def _ip_to_int(ip_str):
    return int(ipaddress.ip_address(ip_str))
