import pkg_resources
from dns import resolver, exception
from yawast.shared import output


def find_srv_records(domain, path=None):
    records = []

    # read the data in from the data directory
    if path is None:
        file_path = pkg_resources.resource_filename("yawast", "resources/srv.txt")
    else:
        file_path = path

    with open(file_path) as file:
        for line in file:
            host = line.strip() + "." + domain

            try:
                answers = resolver.query(host, "SRV", lifetime=3)

                for data in answers:
                    target = data.target.to_text()
                    port = str(data.port)

                    records.append([host, target, port])
            except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
                pass
            except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
                output.debug_exception()
                pass

    return records
