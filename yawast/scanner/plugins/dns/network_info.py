from typing import Dict, Any

from yawast.shared import network, output


_failure = False
_cache: Dict[Any, Any] = {}


def network_info(ip):
    global _failure, _cache

    # first, check the cache
    if _cache.get(ip) is not None:
        return _cache[ip]

    # now, make sure we haven't turn this off due to errors
    if _failure:
        return "Network Information disabled due to prior failure"

    try:
        info, code = network.http_json("https://api.iptoasn.com/v1/as/ip/%s" % ip)

        if code == 200:
            ret = "%s - %s" % (info["as_country_code"], info["as_description"])
            _cache[ip] = ret

            return ret
        else:
            _failure = True

            return "IP To ASN Service returned code: %s" % code
    except (ValueError, KeyError) as error:
        output.debug_exception()
        _failure = True
        return "IP To ASN Service error: %s" % str(error)
