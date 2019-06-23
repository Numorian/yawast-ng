import os
from multiprocessing import Manager
from multiprocessing.dummy import Pool

import pkg_resources
from dns import resolver, exception

from yawast.shared import output


def find_subdomains(domain, path=None):
    records = []

    # create processing pool
    # given the amount of waiting we do, go for double the CPU count
    pool = Pool(os.cpu_count() * 2)
    mgr = Manager()
    queue = mgr.Queue()

    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename(
            "yawast", "resources/subdomains.txt"
        )
    else:
        file_path = path

    with open(file_path) as file:
        for line in file:
            host = line.strip() + "." + domain

            pool.apply_async(_get_records_for_domain, (host, queue))

    pool.close()
    pool.join()

    while not queue.empty():
        val = queue.get()
        if len(val) > 0:
            records.extend(val)

    return records


def _get_records_for_domain(host: str, queue):
    records = []

    res = resolver.Resolver()
    res.nameservers.insert(0, "8.8.8.8")
    res.nameservers.insert(0, "1.1.1.1")
    res.search = []

    if not host.endswith("."):
        host = host + "."

    try:
        answers = res.query(host, "CNAME", lifetime=3, raise_on_no_answer=False)

        for data in answers:
            records.append(["CNAME", host, str(data.target)])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    try:
        answers = res.query(host, "A", lifetime=3, raise_on_no_answer=False)

        for data in answers:
            records.append(["A", host, str(data)])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    try:
        answers = res.query(host, "AAAA", lifetime=3, raise_on_no_answer=False)

        for data in answers:
            records.append(["AAAA", host, str(data)])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()
        pass

    queue.put(records)
