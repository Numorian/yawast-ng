#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import pkg_resources
from dns import resolver, exception
from yawast.shared import output


def find_srv_records(domain, path=None):
    records = []

    res = resolver.Resolver()
    res.nameservers.insert(0, "8.8.8.8")
    res.nameservers.insert(0, "1.1.1.1")
    res.search = []

    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename("yawast", "resources/srv.txt")
    else:
        file_path = path

    with open(file_path) as file:
        for line in file:
            host = line.strip() + "." + domain + "."

            try:
                answers = res.query(host, "SRV", lifetime=3, raise_on_no_answer=False)

                for data in answers:
                    target = data.target.to_text()
                    port = str(data.port)

                    records.append([host, target, port])
            except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout) as error:
                output.debug(f"SRV: {host} received error: {str(error)}")
            except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
                output.debug_exception()
                pass

    return records
