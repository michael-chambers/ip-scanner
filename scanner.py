import requests
import logging
import sys
from dns import reversename

LOG = logging.getLogger("ip-scanner")
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_handler.setFormatter(stdout_formatter)
LOG.addHandler(stdout_handler)

IP_ADDRESS = "127.0.0.1"
IIS_VERSION = "7.0"
NGINX_VERSION = "1.2"


def scanner(ip):
    result = {
        "ip_address": ip,
        "server": "N/A",
        "version": "N/A",
        "directory": False
    }
    response = requests.get("http://" + ip)

    # directory = bool
    if response.status_code == 200 and '<title>Index of /</title>' in response.text:
        result.update({"directory": True})

    if "server" in response.headers:
        server_string = response.headers["server"]
        try:
            server, version = server_string.split("/")
            if version:
                result.update({"server": server})
                result.update({"version": version})
        except ValueError:
            result.update({"server": server_string})
    else:
        result.append(ip, "N/A", "N/A", sep='\t')
    return result


print("IP Address", "Server", "Version", "Directory")
print(scanner(IP_ADDRESS))
