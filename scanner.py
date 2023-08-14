import requests
import logging
import sys
from dns import reversename

LOG = logging.getLogger("ip-scanner")
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.debug)
stdout_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_handler.setFormatter(stdout_formatter)
LOG.addHandler(stdout_handler)

IP_ADDRESS = "45.60.121.229"

url = reversename.from_address(IP_ADDRESS)
LOG.debug("Identified URL is %s" % url)
response = requests.get(url)

if response.status_code == 200 and '<title>Index of /</title>' in response.text:
    print('Directory listing is enabled')
else:
    print('Directory listing is not enabled')

if "server" in response.headers:
    server = response.headers["server"]
    print(server)
    if "nginx" in server.lower():
        print("The server is running Nginx.")
    elif "iis" in server.lower():
        print("The server is running IIS.")
else:
    print("The server type could not be determined.")