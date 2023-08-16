import argparse
import logging
import re
import requests

from ipaddress import ip_address
from typing import Tuple

logger = logging.getLogger("ip-scanner")
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s - %(name)s - %(levelname)-8s - %(message)s')
console = logging.StreamHandler()
console.setFormatter(formatter)
logger.addHandler(console)


def make_request(address: str, ip: bool) -> Tuple[str, str, bool]:
    autoindex = False
    server = ""
    version = ""
    server_string = ""

    try:
        logger.debug(f"attempting to connect to {address}")
        if ip:
            response = requests.get("http://" + address)
        else:
            response = requests.get(address)
        if response:
            logger.debug(f"successfully connected to {address}")
        else:
            raise requests.ConnectionError
        if response.status_code == 200 and '<title>Index of /</title>' in response.text:
            autoindex = True
            logger.debug(f"directory listing discovered at {address}")
        else:
            logger.debug(f"no directory listing found for {address}")
        if "server" in response.headers:
            server_string = response.headers["server"]
            logger.debug(f"server header for {address}: {server_string}")
        else:
            logger.debug(f"no server HTTP header returned for {address}")
    except (ConnectionRefusedError, requests.ConnectionError):
        logger.error(f"unable to connect to {address}")
    except requests.Timeout:
        logger.error(f"timed-out while attempting to connection to {address}")

    if server_string:
        try:
            server, version = server_string.split("/")
        except ValueError:
            server = server_string
            logger.warning(f"Could not determine web server version for {address}")

    return server, version, autoindex


def validate_ip(ip_address: str) -> bool:
    match = re.search("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip_address)
    if match:
        return True
    else:
        logger.error(f"{ip_address} is not a valid IPv4 address, skipping")
        return False


def validate_url(url: str) -> bool:
    match = re.search("^((http|https)://)[-a-zA-Z0-9@:%._\\+~#?&=]{2,256}.[a-z]{2,6}$", url)
    if match:
        return True
    else:
        logger.error(f"{url} is not a valid URL for this tool, must include protocol and no subdirectories, skipping")
        return False


def init_argparse():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="A tool to detect specified versions of NGINX or \
            IIS web servers, as well as find directory listings at the root level"
    )
    parser.add_argument(
        "--debug", "-d", action="store_true", help="turn on debug mode"
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
    parser.add_argument(
        "--url", "-u", action="append", help="a fully-qualified URL to scan (e.g. http://www.example.com), can be used multiple times"
    )
    return parser


def main():
    def process_results(address):
        if directory_listing:
            dir_listing_ips.append(address)

        if server.lower() == "nginx" and version \
                and version.startswith(nginx_version + "."):
            server_version_ips.append([address, server + "/" + version])
        elif server.lower() == ("microsoft-iis") and version \
                and version.startswith(iis_version):
            server_version_ips.append([address, server + "/" + version])

    range = []
    urls = []

    parser = init_argparse()
    args = parser.parse_args()
    iis_version = args.iis
    nginx_version = args.nginx

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.start_ip and args.end_ip:
        start = ip_address(args.start_ip)
        end = ip_address(args.end_ip)
        if start > end and validate_ip(start) and validate_ip(end):
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
            if validate_ip(ip_addr):
                range.append(ip_addr)
    logger.debug(f"selected IPs: {range}")

    if args.url:
        for u in args.url:
            if validate_url(u):
                urls.append(u)

    dir_listing_ips = []
    server_version_ips = []

    for ip in range:
        server = ""
        version = ""
        server, version, directory_listing = make_request(ip, True)
        process_results(ip)

    for url in urls:
        server = ""
        version = ""
        server, version, directory_listing = make_request(url, False)
        process_results(url)

    logger.info("### IPs/URLs with directory listing at root level ###")
    for d in dir_listing_ips:
        logger.info(d)
    logger.info(f"### IPs/URLs matching server version parameters (Microsoft-IIS/{iis_version} or Nginx/{nginx_version}.x ###)")
    for s in server_version_ips:
        logger.info(f"{s[0]}  {s[1]}")


if __name__ == "__main__":
    main()
