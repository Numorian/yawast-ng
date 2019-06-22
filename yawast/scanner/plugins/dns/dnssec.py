from dns import resolver, exception, dnssec
from yawast.shared import output


def get_dnskey(domain):
    records = []

    try:
        answers = resolver.query(domain, "DNSKEY")

        for data in answers:
            flags = format(data.flags, "016b")
            proto = data.protocol
            alg = dnssec.algorithm_to_text(data.algorithm)
            key = data.key

            records.append([flags, proto, alg, key])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return records
