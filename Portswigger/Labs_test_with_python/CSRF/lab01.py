import requests

url = "https://0a4f008504c83dafc07450e9003f007b.web-security-academy.net/my-account/change-email"

data = {
	"email": "test@test2.com"
}

cookies = {
	"session": "ZVCrXoUWWZoIUkHRUsB8uxaA2ebMb7nr"
}

r = requests.post(url, data=data, cookies=cookies)

print(r.text)