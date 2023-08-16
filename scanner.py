import argparse
import logging
import requests

from ipaddress import ip_address

logger = logging.getLogger("ip-scanner")
logger.setLevel(logging.DEBUG)

console = logging.StreamHandler()
logger.addHandler(console)

# TODO parameterize these values
IP_ADDRESS = "127.0.0.1"


def scanner(ip):
    autoindex = False

    # TODO deal with potential errors, such as connectivity issues
    response = requests.get("http://" + ip)
    if response.status_code == 200 and '<title>Index of /</title>' in response.text:
        autoindex = True
    if "server" in response.headers:
        server = response.headers["server"]

    return server, autoindex


def init_argparse():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="A tool to detect specified versions of NGINX or \
            IIS web servers, as well as find directory listings at the root level"
    )
    parser.add_argument(
        "--iis", help="IIS version to search for (default 7.0)", default="7.0",
    )
    parser.add_argument(
        "--nginx", help="NGINX version to search for (default 1.2)", default="1.2"
    )
    parser.add_argument(
        "--start-ip", help="first IP address in a range, cannot be used with --ip-address"
    )
    parser.add_argument(
        "--end-ip", help="last IP address in a range, cannot be used with --ip-address"
    )
    parser.add_argument(
        "-i", "--ip-address", action="append", help="a single IP address to scan, can be used multiple times, cannot be used with --start-ip or --end-ip"
    )
    return parser


parser = init_argparse()
args = parser.parse_args()
IIS_VERSION = args.iis
NGINX_VERSION = args.nginx
if args.start_ip and args.end_ip:
    start = ip_address(args.start_ip)
    end = ip_address(args.end_ip)
    if start > end:
        logger.error("Starting IP address must be sequentially lower than ending IP address")
    range = []
    while start <= end:
        range.append(str(start))
        start += 1
    print(range)
elif args.start_ip and not args.end_ip:
    logger.error("Must specify an ending address in the IP range")
elif args.end_ip and not args.start_ip:
    logger.error("Must specify a beginning address in the IP range")
server_string, directory_listing = scanner(IP_ADDRESS)
dir_listing_ips = list()
server_version_ips = list()
server = str()
version = str()

if server_string:
    try:
        server, version = server_string.split("/")
    except ValueError:
        server = server_string
        logger.debug(f"Could not determine web server version for {IP_ADDRESS}")

if directory_listing:
    dir_listing_ips.append(IP_ADDRESS)

if server.lower() == "nginx" and version \
        and version.startswith(NGINX_VERSION + "."):
    server_version_ips.append([IP_ADDRESS, server + "/" + version])
elif server.lower() == ("microsoft-iis") and version \
        and version.startswith(IIS_VERSION):
    server_version_ips.append([IP_ADDRESS, server + "/" + version])

print("IPs with directory listing at root level")
print(dir_listing_ips)
print(f"IPs matching server version parameters (Microsoft-IIS/{IIS_VERSION} or Nginx/{NGINX_VERSION}.x)")
print(server_version_ips)
