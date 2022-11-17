import requests

url = "https://0a0900ce0319a5f5c1b7af1a002500d7.web-security-academy.net/my-account/change-email"

data = {
	"email": "test@test2.com"
}

cookies = {
	"session": "C0xlH9fRO5WAKw10pxzYIh50MdUuUph0"
}

r = requests.get(url, params=data, cookies=cookies)

print(r.text)
