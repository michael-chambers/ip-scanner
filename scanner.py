import argparse
import logging
import requests

from ipaddress import ip_address

logger = logging.getLogger("ip-scanner")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)-8s - %(message)s')
console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)


def scanner(ip):
    autoindex = False
    server = ""

    # TODO deal with potential errors, such as connectivity issues
    try:
        response = requests.get("http://" + ip)
        if response.status_code == 200 and '<title>Index of /</title>' in response.text:
            autoindex = True
        if "server" in response.headers:
            server = response.headers["server"]
    except (ConnectionRefusedError, requests.ConnectionError):
        logger.error(f"unable to connect to {ip}")
    except requests.Timeout:
        logger.error(f"timed-out while attempting to connection to {ip}")

    return server, autoindex


def init_argparse():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="A tool to detect specified versions of NGINX or \
            IIS web servers, as well as find directory listings at the root level"
    )
    parser.add_argument(
        "--debug", "-d", help="turn on debug mode"  # TODO make this turn on debug mode (default mode should be info)
    )
    parser.add_argument(
        "--iis", help="IIS version to search for (default 7.0)", default="7.0"
    )
    parser.add_argument(
        "--nginx", help="NGINX version to search for (default 1.2)", default="1.2"
    )
    parser.add_argument(
        "-i", "--ip-address", action="append", help="a single IP address to scan, can be used multiple times"
    )
    parser.add_argument(
        "--start-ip", help="first IP address in a range"
    )
    parser.add_argument(
        "--end-ip", help="last IP address in a range"
    )
    return parser


range = []
dir_listing_ips = []
server_version_ips = []

parser = init_argparse()
args = parser.parse_args()
IIS_VERSION = args.iis
NGINX_VERSION = args.nginx

if args.start_ip and args.end_ip:
    start = ip_address(args.start_ip)
    end = ip_address(args.end_ip)
    if start > end:
        logger.error("Starting IP address must be sequentially lower than ending IP address")
    else:
        while start <= end:
            range.append(str(start))
            start += 1
elif args.start_ip and not args.end_ip:
    logger.error("Must specify an ending address in the IP range")
elif args.end_ip and not args.start_ip:
    logger.error("Must specify a beginning address in the IP range")

if args.ip_address:
    for ip_addr in args.ip_address:
        range.append(ip_addr)
logger.debug(f"selected IPs: {range}")

for ip in range:
    server = str()
    version = str()
    server_string, directory_listing = scanner(ip)

    if server_string:
        try:
            server, version = server_string.split("/")
        except ValueError:
            server = server_string
            logger.warning(f"Could not determine web server version for {ip}")

    if directory_listing:
        dir_listing_ips.append(ip)

    if server.lower() == "nginx" and version \
            and version.startswith(NGINX_VERSION + "."):
        server_version_ips.append([ip, server + "/" + version])
    elif server.lower() == ("microsoft-iis") and version \
            and version.startswith(IIS_VERSION):
        server_version_ips.append([ip, server + "/" + version])

logger.info("### IPs with directory listing at root level ###")
for d in dir_listing_ips:
    logger.info(d)
logger.info(f"### IPs matching server version parameters (Microsoft-IIS/{IIS_VERSION} or Nginx/{NGINX_VERSION}.x ###)")
for s in server_version_ips:
    logger.info(f"{s[0]}  {s[1]}")
