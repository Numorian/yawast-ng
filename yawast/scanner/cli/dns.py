import ipaddress
import socket

from publicsuffixlist import PublicSuffixList

from yawast.reporting import reporter, issue
from yawast.reporting.enums import Vulnerabilities, Severity
from yawast.scanner.plugins.dns import basic
from yawast.scanner.plugins.dns import caa
from yawast.scanner.plugins.dns import dnssec
from yawast.scanner.plugins.dns import network_info
from yawast.scanner.plugins.dns import srv
from yawast.scanner.plugins.dns import subdomains
from yawast.shared import utils, output


def scan(args, url, domain):
    # check to see if this is an IP, if so, bail out
    if utils.is_ip(domain):
        return

    output.empty()
    output.norm("DNS Information:")

    # get the root domain, by looking up via the PSL
    psl = PublicSuffixList()
    root_domain = psl.privatesuffix(domain)

    # IP Addresses for the domain we are scanning
    ips = basic.get_ips(domain)
    for ip in ips:
        output.norm("\t%s (%s)" % (ip, basic.get_host(str(ip))))

        addr = ipaddress.ip_address(str(ip))

        if not addr.is_private:
            ni = network_info.network_info(str(ip))
            output.norm("\t\t%s" % ni)

            if addr.version == 4:
                output.norm("\t\thttps://www.shodan.io/host/%s" % ip)
                output.norm("\t\thttps://censys.io/ipv4/%s" % ip)
            else:
                output.norm("\t\thttps://www.shodan.io/host/%s" % str(ip).lower())

        output.empty()

    # TXT records for the domain we are scanning
    txt = basic.get_text(domain)
    for rec in txt:
        output.norm("\tTXT: %s" % rec)

    # TXT records for the root domain
    if root_domain != domain:
        txt = basic.get_text(root_domain)
        for rec in txt:
            output.norm("\tTXT (%s): %s" % (root_domain, rec))

    output.empty()

    # MX records for the domain we are scanning
    mx = basic.get_mx(domain)
    for rec in mx:
        server_ip = socket.gethostbyname(rec[0])
        ni = network_info.network_info(str(server_ip))

        info = "%s (%s) - %s (%s)" % (rec[0], rec[1], server_ip, ni)
        output.norm("\tMX: %s" % info)

    # MX records for the root domain
    if root_domain != domain:
        mx = basic.get_mx(root_domain)
        for rec in mx:
            server_ip = socket.gethostbyname(rec[0])
            ni = network_info.network_info(str(server_ip))

            info = "%s (%s) - %s (%s)" % (rec[0], rec[1], server_ip, ni)
            output.norm("\tMX (%s): %s" % (root_domain, info))

    output.empty()

    # NS records for the root domain
    ns = basic.get_ns(root_domain)
    for rec in ns:
        server_ip = socket.gethostbyname(rec)
        ni = network_info.network_info(str(server_ip))

        info = "%s - %s (%s)" % (rec, server_ip, ni)
        output.norm("\tNS: %s" % info)

    output.empty()

    if args.srv:
        output.norm("Searching for SRV records, this will take a minute...")
        output.empty()

        srv_records = srv.find_srv_records(root_domain)
        for rec in srv_records:
            server_ip = socket.gethostbyname(rec[1])
            ni = network_info.network_info(str(server_ip))

            info = "%s: %s:%s - %s (%s)" % (rec[0], rec[1], rec[2], server_ip, ni)
            output.norm("\tSRV: %s" % info)

        output.empty()

    if args.subdomains:
        output.norm("Searching for sub-domains, this will take a few minutes...")
        output.empty()

        sds = subdomains.find_subdomains(root_domain)
        for rec in sds:
            info = ""

            if rec[0] == "CNAME":
                server_ip = socket.gethostbyname(rec[2])
                ni = network_info.network_info(str(server_ip))

                info = "(CNAME) %s -> %s - %s (%s)" % (rec[1], rec[2], server_ip, ni)
            elif rec[0] == "A":
                ni = network_info.network_info(rec[2])
                info = "(A) %s: %s (%s)" % (rec[1], rec[2], ni)
            elif rec[0] == "AAAA":
                ni = network_info.network_info(rec[2])
                info = "(AAAA) %s: %s (%s)" % (rec[1], rec[2], ni)

            output.norm("\tSubdomain: %s" % info)

        output.empty()

    caa_count = 0
    carec = caa.get_caa(domain)
    for rec in carec:
        curr = rec[0]

        if rec[1] == "CNAME":
            output.norm("\tCAA (%s): CNAME Found: -> %s" % (curr, rec[2]))
        elif rec[1] == "CAA":
            if len(rec[2]) > 0:
                for line in rec[2]:
                    output.norm('\tCAA (%s): "%s"' % (curr, line))
                    caa_count += 1
            else:
                output.norm("\tCAA (%s): No Records Found" % curr)

    output.empty()

    # notify the user if there's an issue
    if caa_count == 0:
        reporter.display(
            "\tCAA: Domain does not have protection from CAA",
            issue.Issue(Vulnerabilities.DNS_CAA_MISSING, url),
        )

    dk = dnssec.get_dnskey(domain)
    if len(dk) > 0:
        for rec in dk:
            output.norm(
                "\tDNSKEY: Algorithm: '%s' - Flags: '%s' - Key Length: %s"
                % (rec[2], rec[0], len(rec[3]) * 8)
            )
    else:
        reporter.display(
            "\tDNSKEY: Domain does not use DNSSEC",
            issue.Issue(Vulnerabilities.DNS_CAA_MISSING, url),
        )

    output.empty()
