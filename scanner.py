import requests

url = "https://www.digicert.com"

response = requests.get(url)

if "server" in response.headers:
    server = response.headers["server"]
    print(server)
    if "nginx" in server.lower():
        print("The server is running Nginx.")
    elif "iis" in server.lower():
        print("The server is running IIS.")
else:
    print("The server type could not be determined.")