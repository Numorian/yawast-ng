from dns import resolver, exception, reversename
from yawast.shared import output


def get_ips(domain: str):
    ips = []

    try:
        answers_v4 = resolver.query(domain, "A")

        for data in answers_v4:
            ips.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    try:
        answers_v6 = resolver.query(domain, "AAAA")
        for data in answers_v6:
            ips.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return ips


def get_text(domain):
    records = []

    try:
        answers = resolver.query(domain, "TXT")

        for data in answers:
            records.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return records


def get_mx(domain):
    records = []

    try:
        answers = resolver.query(domain, "MX")

        for data in answers:
            records.append([str(data.exchange), str(data.preference)])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return records


def get_ns(domain):
    records = []

    try:
        answers = resolver.query(domain, "NS")

        for data in answers:
            records.append(str(data))
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return records


def get_host(ip):
    name = "N/A"

    try:
        rev_name = reversename.from_address(str(ip))
        name = str(resolver.query(rev_name, "PTR", lifetime=3)[0])[:-1]
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return name
