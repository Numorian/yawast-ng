from dns import resolver, exception
from yawast.shared import output
import copy


_checked = {}
_results = []


def get_caa(domain):
    global _checked, _results

    # force DNS resolver to something that works
    # this is done to ensure that ISP resolvers don't get in the way
    # at some point, should probably do something else, but works for now
    # (Cloudflare & Google)
    resv = resolver.Resolver()
    resv.nameservers = ["1.1.1.1", "8.8.8.8"]

    _chase_domain(domain, resv)

    # reset global data
    ret = copy.deepcopy(_results)
    _results = []
    _checked = {}

    return ret


def _chase_domain(domain, resv):
    global _checked, _results
    curr = domain

    while curr is not None:
        # check to see if we've already ran into this one
        if _checked.get(curr) is not None:
            return

        _checked[curr] = True

        # first, see if this is a CNAME. we do this explicitly because
        # some resolvers flatten in an odd way that prevents just checking
        # for the CAA record directly
        cname = _get_cname(curr, resv)
        if cname is not None:
            _results.append([curr, "CNAME", cname])
            _chase_domain(cname.rstrip("."), resv)
        else:
            caa = _get_caa_records(curr, resv)
            _results.append([curr, "CAA", caa])

        if "." in curr:
            curr = curr.split(".", 1)[-1]
        else:
            curr = None


def _get_caa_records(domain, resv):
    records = []

    try:
        answers = resv.query(domain, "CAA", lifetime=3)

        for data in answers:
            records.append(data.to_text())
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return records


def _get_cname(domain, resv):
    name = None

    try:
        answers = resv.query(domain, "CNAME", lifetime=3)

        for data in answers:
            name = str(data.target)
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    return name
