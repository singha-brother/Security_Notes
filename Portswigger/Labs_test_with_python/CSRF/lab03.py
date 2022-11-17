import requests

url = "https://0aa500cd0447a17fc0604986003c0082.web-security-academy.net/my-account/change-email"

data = {
	"email": "test@test2.com"
}

cookies = {
	"session": "HlKIgo5A2EbDryKNN993OYz6h5Hg6ZG9"
}

r = requests.post(url, data=data, cookies=cookies)

print(r.text)
