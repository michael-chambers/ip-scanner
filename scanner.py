import requests
import logging

logger = logging.getLogger("ip-scanner")
logger.setLevel(logging.DEBUG)
console = logging.StreamHandler()
logger.addHandler(console)

# TODO parameterize these values
IP_ADDRESS = "127.0.0.1"
IIS_VERSION = "7.0"
NGINX_VERSION = "1.25"


def scanner(ip):
    autoindex = False

    # TODO deal with potential errors, such as connectivity issues
    response = requests.get("http://" + ip)
    if response.status_code == 200 and '<title>Index of /</title>' in response.text:
        autoindex = True
    if "server" in response.headers:
        server = response.headers["server"]

    return server, autoindex


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
