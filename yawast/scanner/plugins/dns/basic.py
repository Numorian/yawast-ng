#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from dns import resolver, exception, reversename

from yawast.shared import output


def get_ips(domain: str):
    ips = []

    try:
        answers_v4 = resolver.resolve(domain, "A")

        for data in answers_v4:
            ips.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    try:
        answers_v6 = resolver.resolve(domain, "AAAA")
        for data in answers_v6:
            ips.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return ips


def get_text(domain):
    records = []

    try:
        answers = resolver.resolve(domain, "TXT")

        for data in answers:
            records.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return records


def get_mx(domain):
    records = []

    try:
        answers = resolver.resolve(domain, "MX")

        for data in answers:
            records.append([str(data.exchange), str(data.preference)])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return records


def get_ns(domain):
    records = []

    try:
        answers = resolver.resolve(domain, "NS")

        for data in answers:
            records.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return records


def get_host(ip):
    name = "N/A"

    try:
        rev_name = reversename.from_address(str(ip))
        name = str(resolver.resolve(rev_name, "PTR", lifetime=3)[0])[:-1]
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return name
